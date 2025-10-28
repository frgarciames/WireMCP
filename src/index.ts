import cors from "cors";
import express, { type Express } from "express";
import { mcpRouter } from "./mcp.js";

const app: Express = express();
const PORT = parseInt(process.env.PORT || "3001", 10);
const HOST = process.env.HOST || "0.0.0.0";

// Middleware
// allow all
app.use(
	cors({
		allowedHeaders: [
			"x-org",
			"authorization",
			"content-type",
			"mcp-session-id",
			"mcp-protocol-version",
		],
		exposedHeaders: ["mcp-session-id"],
		origin: "*",
	}),
);
app.use(express.json());

// Health check endpoint
app.get("/health", (_req, res) => {
	res.json({
		status: "ok",
		server: "wireshark-mcp-server",
		version: "1.0.0",
	});
});

// Mount MCP router
app.use("/mcp", mcpRouter);

// Error handling middleware
app.use(
	(
		err: Error,
		_req: express.Request,
		res: express.Response,
		_next: express.NextFunction,
	) => {
		console.error("Server error:", err);
		res.status(500).json({
			error: "Internal server error",
			message: err.message,
		});
	},
);

// Start server
const server = app.listen(PORT, HOST, () => {
	console.log(`MCP Server running on http://${HOST}:${PORT}`);
	console.log(`MCP endpoint: http://${HOST}:${PORT}/mcp`);
	console.log(`Health check: http://${HOST}:${PORT}/health`);
});

// Graceful shutdown
const gracefulShutdown = (signal: string) => {
	console.log(`\n${signal} received, shutting down gracefully...`);
	server.close(() => {
		console.log("Server closed");
		process.exit(0);
	});

	// Force shutdown after 10 seconds
	setTimeout(() => {
		console.error("Forced shutdown after timeout");
		process.exit(1);
	}, 10000);
};

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

// Handle uncaught errors
process.on("uncaughtException", (error: Error) => {
	console.error("Uncaught Exception:", error);
	process.exit(1);
});

process.on("unhandledRejection", (reason: any) => {
	console.error("Unhandled Rejection:", reason);
	process.exit(1);
});

export default app;
