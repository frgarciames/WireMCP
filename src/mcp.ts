import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { type Request, type Response, Router } from "express";
import { handleToolCall, toolsList } from "./tools.js";

export const mcpRouter: Router = Router();
const SERVER_NAME = "wiremcp";
const SERVER_VERSION = "1.0.0";

// Session configuration
const SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes
const MAX_SESSIONS = 100;
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

interface SessionInfo {
	transport: StreamableHTTPServerTransport;
	lastActivity: number;
}

const sessions: Map<string, SessionInfo> = new Map();

// Cleanup expired sessions periodically
setInterval(() => {
	const now = Date.now();
	const expiredSessions: string[] = [];

	sessions.forEach((session, sessionId) => {
		if (now - session.lastActivity > SESSION_TIMEOUT_MS) {
			expiredSessions.push(sessionId);
		}
	});

	expiredSessions.forEach((sessionId) => {
		console.log(`Cleaning up expired session: ${sessionId}`);
		const session = sessions.get(sessionId);
		if (session?.transport.sessionId) {
			// Close the transport if possible
			try {
				session.transport.close?.();
			} catch (err) {
				console.error(`Error closing transport for session ${sessionId}:`, err);
			}
		}
		sessions.delete(sessionId);
	});

	if (expiredSessions.length > 0) {
		console.log(`Cleaned up ${expiredSessions.length} expired session(s)`);
	}
}, CLEANUP_INTERVAL_MS);

// Create and configure a new MCP server
function createMcpServer(): McpServer {
	const server = new McpServer({
		name: SERVER_NAME,
		version: SERVER_VERSION,
	});

	// Register all tools with their implementations
	toolsList.forEach((tool) => {
		server.registerTool(
			tool.name,
			{
				title: tool.name,
				description: tool.description,
				inputSchema: tool.inputSchema as any,
			},
			// @ts-expect-error
			async (args: any) => {
				console.log(`Executing tool: ${tool.name}`, args);
				try {
					const result = await handleToolCall(tool.name, args);
					return result;
				} catch (error) {
					const err = error as Error;
					console.error(`Error executing tool ${tool.name}:`, err.message);
					return {
						content: [
							{
								type: "text",
								text: `Error executing ${tool.name}: ${err.message}`,
							},
						],
						isError: true,
					};
				}
			},
		);
	});

	return server;
}

// Main POST handler for MCP requests
mcpRouter.post("/", async (req: Request, res: Response) => {
	try {
		const sessionId = req.headers["mcp-session-id"] as string | undefined;
		let sessionInfo: SessionInfo | undefined;

		// Handle existing session
		if (sessionId && sessions.has(sessionId)) {
			sessionInfo = sessions.get(sessionId)!;
			sessionInfo.lastActivity = Date.now();

			await sessionInfo.transport.handleRequest(req, res, req.body);
			return;
		}

		// Handle new session (initialize request)
		if (isInitializeRequest(req.body)) {
			// Check session limit
			if (sessions.size >= MAX_SESSIONS) {
				// Remove oldest session
				const oldestSession = Array.from(sessions.entries()).reduce(
					(oldest, current) =>
						current[1].lastActivity < oldest[1].lastActivity ? current : oldest,
				);
				console.log(
					`Max sessions reached. Removing oldest: ${oldestSession[0]}`,
				);
				sessions.delete(oldestSession[0]);
			}

			const transport = new StreamableHTTPServerTransport({
				sessionIdGenerator: () => randomUUID(),
				onsessioninitialized: (newSessionId) => {
					console.log(`New session initialized: ${newSessionId}`);
					sessions.set(newSessionId, {
						transport,
						lastActivity: Date.now(),
					});
				},
			});

			transport.onclose = () => {
				if (transport.sessionId) {
					console.log(`Session closed: ${transport.sessionId}`);
					sessions.delete(transport.sessionId);
				}
			};

			const server = createMcpServer();
			await server.connect(transport);
			await transport.handleRequest(req, res, req.body);
			return;
		}

		// Invalid request - no session and not an initialize request
		res.status(400).json({
			jsonrpc: "2.0",
			error: {
				code: -32000,
				message:
					"Bad Request: No valid session ID provided and not an initialize request",
			},
			id: null,
		});
	} catch (error) {
		const err = error as Error;
		console.error("Error handling POST request:", err);
		res.status(500).json({
			jsonrpc: "2.0",
			error: {
				code: -32603,
				message: `Internal error: ${err.message}`,
			},
			id: null,
		});
	}
});

// Handle session-specific requests (GET/DELETE)
const handleSessionRequest = async (req: Request, res: Response) => {
	try {
		const sessionId = req.headers["mcp-session-id"] as string | undefined;

		if (!sessionId || !sessions.has(sessionId)) {
			res.status(400).json({
				jsonrpc: "2.0",
				error: {
					code: -32000,
					message: "Invalid or missing session ID",
				},
				id: null,
			});
			return;
		}

		const sessionInfo = sessions.get(sessionId)!;
		sessionInfo.lastActivity = Date.now();

		// For GET/DELETE, body might be empty or in query params
		const body = req.method === "GET" ? req.query : req.body;
		await sessionInfo.transport.handleRequest(req, res, body);
	} catch (error) {
		const err = error as Error;
		console.error(`Error handling ${req.method} request:`, err);
		res.status(500).json({
			jsonrpc: "2.0",
			error: {
				code: -32603,
				message: `Internal error: ${err.message}`,
			},
			id: null,
		});
	}
};

mcpRouter.get("/", handleSessionRequest);
mcpRouter.delete("/", handleSessionRequest);

// Health check endpoint
mcpRouter.get("/health", (_req: Request, res: Response) => {
	res.json({
		status: "ok",
		server: SERVER_NAME,
		version: SERVER_VERSION,
		activeSessions: sessions.size,
	});
});

// Graceful shutdown
process.on("SIGTERM", () => {
	console.log("SIGTERM received. Cleaning up sessions...");
	sessions.forEach((session, sessionId) => {
		try {
			session.transport.close?.();
		} catch (err) {
			console.error(`Error closing session ${sessionId}:`, err);
		}
	});
	sessions.clear();
	console.log("All sessions closed");
});
