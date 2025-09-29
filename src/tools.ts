import axios from "axios";
import { exec } from "child_process";
import { promises as fs } from "fs";
import { promisify } from "util";
import which from "which";
import { z } from "zod";

const execAsync = promisify(exec);

// types.ts - Type definitions for WireMCP

export interface ToolCallRequest {
	params: {
		name: string;
		arguments: Record<string, any>;
	};
}

export interface PromptsGetRequest {
	params: {
		name: string;
		arguments?: Record<string, any>;
	};
}

export interface PacketLayer {
	"frame.number"?: string[];
	"ip.src"?: string[];
	"ip.dst"?: string[];
	"tcp.srcport"?: string[];
	"tcp.dstport"?: string[];
	"udp.srcport"?: string[];
	"udp.dstport"?: string[];
	"http.host"?: string[];
	"http.request.uri"?: string[];
	"http.request.method"?: string[];
	"http.response.code"?: string[];
	"http.authbasic"?: string[];
	"frame.protocols"?: string[];
	"frame.time"?: string[];
	"tcp.flags"?: string[];
	"ftp.request.command"?: string[];
	"ftp.request.arg"?: string[];
	"telnet.data"?: string[];
	"kerberos.CNameString"?: string[];
	"kerberos.realm"?: string[];
	"kerberos.cipher"?: string[];
	"kerberos.type"?: string[];
	"kerberos.msg_type"?: string[];
}

export interface Packet {
	_source?: {
		layers: PacketLayer;
	};
}

export interface PlaintextCredential {
	type: string;
	username?: string;
	password?: string;
	data?: string;
	frame: string;
}

export interface EncryptedCredential {
	type: string;
	hash: string;
	username: string;
	realm: string;
	frame: string;
	crackingMode: string;
}

export interface Credentials {
	plaintext: PlaintextCredential[];
	encrypted: EncryptedCredential[];
}

export interface NetworkInterface {
	name: string;
	description: string;
}

export interface CaptureArgs {
	interface?: string;
	duration?: number;
}

export interface CheckIPArgs {
	ip: string;
}

export interface AnalyzePcapArgs {
	pcapPath: string;
}

export interface ToolResponse {
	content: Array<{
		type: string;
		text: string;
	}>;
	isError?: boolean;
}

export interface PromptMessage {
	role: string;
	content: {
		type: string;
		text: string;
	};
}

export interface PromptResponse {
	messages: PromptMessage[];
}

export interface ToolDefinition {
	name: string;
	description: string;
	inputSchema: Record<string, z.ZodTypeAny>;
}

export interface PromptDefinition {
	name: string;
	description: string;
	arguments: Array<{
		name: string;
		description: string;
		required: boolean;
	}>;
}

// Dynamically locate tshark
async function findTshark(): Promise<string> {
	try {
		const tsharkPath = await which("tshark");
		console.log(`Found tshark at: ${tsharkPath}`);
		return tsharkPath;
	} catch (err) {
		const error = err as Error;
		console.log("which failed to find tshark:", error.message);
		const fallbacks =
			process.platform === "win32"
				? [
						"C:\\Program Files\\Wireshark\\tshark.exe",
						"C:\\Program Files (x86)\\Wireshark\\tshark.exe",
					]
				: [
						"/usr/bin/tshark",
						"/usr/local/bin/tshark",
						"/opt/homebrew/bin/tshark",
						"/Applications/Wireshark.app/Contents/MacOS/tshark",
					];

		for (const path of fallbacks) {
			try {
				await execAsync(`${path} -v`);
				console.log(`Found tshark at fallback: ${path}`);
				return path;
			} catch (e) {
				const fallbackError = e as Error;
				console.log(`Fallback ${path} failed: ${fallbackError.message}`);
			}
		}
		throw new Error(
			"tshark not found. Please install Wireshark (https://www.wireshark.org/download.html) and ensure tshark is in your PATH.",
		);
	}
}

export const toolsList: ToolDefinition[] = [
	{
		name: "capture_packets",
		description:
			"Capture live traffic and provide raw packet data as JSON for LLM analysis",
		inputSchema: {
			interface: z
				.string()
				.default("en0")
				.describe("Network interface to capture from (e.g., eth0, en0)"),
			duration: z.number().default(5).describe("Capture duration in seconds"),
		},
	},
	{
		name: "get_summary_stats",
		description:
			"Capture live traffic and provide protocol hierarchy statistics for LLM analysis",
		inputSchema: {
			interface: z
				.string()
				.default("en0")
				.describe("Network interface to capture from (e.g., eth0, en0)"),
			duration: z.number().default(5).describe("Capture duration in seconds"),
		},
	},
	{
		name: "get_conversations",
		description:
			"Capture live traffic and provide TCP/UDP conversation statistics for LLM analysis",
		inputSchema: {
			interface: z
				.string()
				.default("en0")
				.describe("Network interface to capture from (e.g., eth0, en0)"),
			duration: z.number().default(5).describe("Capture duration in seconds"),
		},
	},
	{
		name: "check_threats",
		description: "Capture live traffic and check IPs against URLhaus blacklist",
		inputSchema: {
			interface: z
				.string()
				.default("en0")
				.describe("Network interface to capture from (e.g., eth0, en0)"),
			duration: z.number().default(5).describe("Capture duration in seconds"),
		},
	},
	{
		name: "check_ip_threats",
		description: "Check a given IP address against URLhaus blacklist for IOCs",
		inputSchema: {
			ip: z
				.string()
				.regex(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/)
				.describe("IP address to check (e.g., 192.168.1.1)"),
		},
	},
	{
		name: "analyze_pcap",
		description:
			"Analyze a PCAP file and provide general packet data as JSON for LLM analysis",
		inputSchema: {
			pcapPath: z
				.string()
				.describe("Path to the PCAP file to analyze (e.g., ./demo.pcap)"),
		},
	},
	{
		name: "extract_credentials",
		description:
			"Extract potential credentials (HTTP Basic Auth, FTP, Telnet) from a PCAP file for LLM analysis",
		inputSchema: {
			pcapPath: z
				.string()
				.describe("Path to the PCAP file to analyze (e.g., ./demo.pcap)"),
		},
	},
];

// Tool implementations
export async function handleToolCall(name: string, args: any) {
	// TOOL 1: capture_packets
	if (name === "capture_packets") {
		console.log("Tool call: capture_packets", args);
		try {
			const tsharkPath = await findTshark();
			const { interface: iface = "en0", duration = 5 } = args;
			const tempPcap = `temp_capture_${Date.now()}.pcap`;
			console.log(`Capturing packets on ${iface} for ${duration}s`);

			await execAsync(
				`${tsharkPath} -i ${iface} -w ${tempPcap} -a duration:${duration}`,
				{
					env: {
						...process.env,
						PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin`,
					},
				},
			);

			const { stdout, stderr } = await execAsync(
				`${tsharkPath} -r "${tempPcap}" -T json -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags -e frame.time -e http.request.method -e http.response.code`,
				{
					env: {
						...process.env,
						PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin`,
					},
				},
			);
			if (stderr) console.log(`tshark stderr: ${stderr}`);
			let packets: Packet[] = JSON.parse(stdout);

			const maxChars = 720000;
			let jsonString = JSON.stringify(packets);
			if (jsonString.length > maxChars) {
				const trimFactor = maxChars / jsonString.length;
				const trimCount = Math.floor(packets.length * trimFactor);
				packets = packets.slice(0, trimCount);
				jsonString = JSON.stringify(packets);
				console.log(
					`Trimmed packets from ${packets.length} to ${trimCount} to fit ${maxChars} chars`,
				);
			}

			await fs
				.unlink(tempPcap)
				.catch((err: Error) =>
					console.log(`Failed to delete ${tempPcap}: ${err.message}`),
				);

			return {
				content: [
					{
						type: "text",
						text: `Captured packet data (JSON for LLM analysis):\n${jsonString}`,
					},
				],
			};
		} catch (error) {
			const err = error as Error;
			console.log(`Error in capture_packets: ${err.message}`);
			return {
				content: [{ type: "text", text: `Error: ${err.message}` }],
				isError: true,
			};
		}
	}

	// TOOL 2: get_summary_stats
	if (name === "get_summary_stats") {
		try {
			const tsharkPath = await findTshark();
			const { interface: iface = "en0", duration = 5 } = args;
			const tempPcap = `temp_capture_${Date.now()}.pcap`;
			console.log(`Capturing summary stats on ${iface} for ${duration}s`);

			await execAsync(
				`${tsharkPath} -i ${iface} -w ${tempPcap} -a duration:${duration}`,
				{
					env: {
						...process.env,
						PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin`,
					},
				},
			);

			const { stdout, stderr } = await execAsync(
				`${tsharkPath} -r "${tempPcap}" -qz io,phs`,
				{
					env: {
						...process.env,
						PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin`,
					},
				},
			);
			if (stderr) console.log(`tshark stderr: ${stderr}`);

			await fs
				.unlink(tempPcap)
				.catch((err: Error) =>
					console.log(`Failed to delete ${tempPcap}: ${err.message}`),
				);

			return {
				content: [
					{
						type: "text",
						text: `Protocol hierarchy statistics for LLM analysis:\n${stdout}`,
					},
				],
			};
		} catch (error) {
			const err = error as Error;
			console.log(`Error in get_summary_stats: ${err.message}`);
			return {
				content: [{ type: "text", text: `Error: ${err.message}` }],
				isError: true,
			};
		}
	}

	// TOOL 3: get_conversations
	if (name === "get_conversations") {
		try {
			const tsharkPath = await findTshark();
			const { interface: iface = "en0", duration = 5 } = args;
			const tempPcap = `temp_capture_${Date.now()}.pcap`;
			console.log(`Capturing conversations on ${iface} for ${duration}s`);

			await execAsync(
				`${tsharkPath} -i ${iface} -w ${tempPcap} -a duration:${duration}`,
				{
					env: {
						...process.env,
						PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin`,
					},
				},
			);

			const { stdout, stderr } = await execAsync(
				`${tsharkPath} -r "${tempPcap}" -qz conv,tcp`,
				{
					env: {
						...process.env,
						PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin`,
					},
				},
			);
			if (stderr) console.log(`tshark stderr: ${stderr}`);

			await fs
				.unlink(tempPcap)
				.catch((err: Error) =>
					console.log(`Failed to delete ${tempPcap}: ${err.message}`),
				);

			return {
				content: [
					{
						type: "text",
						text: `TCP/UDP conversation statistics for LLM analysis:\n${stdout}`,
					},
				],
			};
		} catch (error) {
			const err = error as Error;
			console.log(`Error in get_conversations: ${err.message}`);
			return {
				content: [{ type: "text", text: `Error: ${err.message}` }],
				isError: true,
			};
		}
	}

	// TOOL 4: check_threats
	if (name === "check_threats") {
		try {
			const tsharkPath = await findTshark();
			const { interface: iface = "en0", duration = 5 } = args;
			const tempPcap = `temp_capture_${Date.now()}.pcap`;
			console.log(
				`Capturing traffic on ${iface} for ${duration}s to check threats`,
			);

			await execAsync(
				`${tsharkPath} -i ${iface} -w ${tempPcap} -a duration:${duration}`,
				{
					env: {
						...process.env,
						PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin`,
					},
				},
			);

			const { stdout } = await execAsync(
				`${tsharkPath} -r "${tempPcap}" -T fields -e ip.src -e ip.dst`,
				{
					env: {
						...process.env,
						PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin`,
					},
				},
			);
			const ips = [
				...new Set(
					stdout
						.split("\n")
						.flatMap((line) => line.split("\t"))
						.filter((ip) => ip && ip !== "unknown"),
				),
			];
			console.log(`Captured ${ips.length} unique IPs: ${ips.join(", ")}`);

			const urlhausUrl = "https://urlhaus.abuse.ch/downloads/text/";
			console.log(`Fetching URLhaus blacklist from ${urlhausUrl}`);
			let urlhausData: string[] = [];
			let urlhausThreats: string[] = [];
			try {
				const response = await axios.get(urlhausUrl);
				const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
				urlhausData = [
					...new Set(
						response.data
							.split("\n")
							.map((line: string) => {
								const match = line.match(ipRegex);
								return match ? match[0] : null;
							})
							.filter((ip: string | null): ip is string => ip !== null),
					),
				] as string[];
				console.log(
					`URLhaus lookup successful: ${urlhausData.length} blacklist IPs fetched`,
				);
				urlhausThreats = ips.filter((ip) => urlhausData.includes(ip));
				console.log(
					`Checked IPs against URLhaus: ${urlhausThreats.length} threats found`,
				);
			} catch (e) {
				const err = e as Error;
				console.log(`Failed to fetch URLhaus data: ${err.message}`);
			}

			const outputText =
				`Captured IPs:\n${ips.join("\n")}\n\n` +
				`Threat check against URLhaus blacklist:\n${
					urlhausThreats.length > 0
						? `Potential threats: ${urlhausThreats.join(", ")}`
						: "No threats detected in URLhaus blacklist."
				}`;

			await fs
				.unlink(tempPcap)
				.catch((err: Error) =>
					console.log(`Failed to delete ${tempPcap}: ${err.message}`),
				);

			return {
				content: [{ type: "text", text: outputText }],
			};
		} catch (error) {
			const err = error as Error;
			console.log(`Error in check_threats: ${err.message}`);
			return {
				content: [{ type: "text", text: `Error: ${err.message}` }],
				isError: true,
			};
		}
	}

	// TOOL 5: check_ip_threats
	if (name === "check_ip_threats") {
		try {
			const { ip } = args;
			console.log(`Checking IP ${ip} against URLhaus blacklist`);

			const urlhausUrl = "https://urlhaus.abuse.ch/downloads/text/";
			let isThreat = false;
			try {
				const response = await axios.get(urlhausUrl);
				const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
				const urlhausData = [
					...new Set(
						response.data
							.split("\n")
							.map((line: string) => {
								const match = line.match(ipRegex);
								return match ? match[0] : null;
							})
							.filter((ip: string | null): ip is string => ip !== null),
					),
				] as string[];
				isThreat = urlhausData.includes(ip);
				console.log(
					`IP ${ip} checked: ${isThreat ? "Threat found" : "No threat"}`,
				);
			} catch (e) {
				const err = e as Error;
				console.log(`Failed to fetch URLhaus data: ${err.message}`);
			}

			const outputText =
				`IP checked: ${ip}\n\n` +
				`Threat check against URLhaus blacklist:\n${
					isThreat
						? "Potential threat detected in URLhaus blacklist."
						: "No threat detected in URLhaus blacklist."
				}`;

			return {
				content: [{ type: "text", text: outputText }],
			};
		} catch (error) {
			const err = error as Error;
			console.log(`Error in check_ip_threats: ${err.message}`);
			return {
				content: [{ type: "text", text: `Error: ${err.message}` }],
				isError: true,
			};
		}
	}

	// TOOL 6: analyze_pcap
	if (name === "analyze_pcap") {
		try {
			const tsharkPath = await findTshark();
			const { pcapPath } = args;
			console.log(`Analyzing PCAP file: ${pcapPath}`);

			await fs.access(pcapPath);

			const { stdout, stderr } = await execAsync(
				`${tsharkPath} -r "${pcapPath}" -T json -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e http.host -e http.request.uri -e frame.protocols`,
				{
					env: {
						...process.env,
						PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin`,
					},
				},
			);
			if (stderr) console.log(`tshark stderr: ${stderr}`);
			let packets: Packet[] = JSON.parse(stdout);

			const ips = [
				...new Set(
					packets
						.flatMap((p) => [
							p._source?.layers["ip.src"]?.[0],
							p._source?.layers["ip.dst"]?.[0],
						])
						.filter((ip): ip is string => !!ip),
				),
			];

			const urls = packets
				.filter(
					(p) =>
						p._source?.layers["http.host"] &&
						p._source?.layers["http.request.uri"],
				)
				.map(
					(p) =>
						`http://${p._source!.layers["http.host"]![0]}${
							p._source!.layers["http.request.uri"]![0]
						}`,
				);

			const protocols = [
				...new Set(
					packets
						.map((p) => p._source?.layers["frame.protocols"]?.[0])
						.filter((p): p is string => !!p),
				),
			];

			const maxChars = 720000;
			let jsonString = JSON.stringify(packets);
			if (jsonString.length > maxChars) {
				const trimFactor = maxChars / jsonString.length;
				const trimCount = Math.floor(packets.length * trimFactor);
				packets.splice(trimCount);
				jsonString = JSON.stringify(packets);
				console.log(`Trimmed packets to fit ${maxChars} chars`);
			}

			const outputText =
				`Analyzed PCAP: ${pcapPath}\n\n` +
				`Unique IPs:\n${ips.join("\n")}\n\n` +
				`URLs:\n${urls.length > 0 ? urls.join("\n") : "None"}\n\n` +
				`Protocols:\n${protocols.join("\n") || "None"}\n\n` +
				`Packet Data (JSON for LLM):\n${jsonString}`;

			return {
				content: [{ type: "text", text: outputText }],
			};
		} catch (error) {
			const err = error as Error;
			console.log(`Error in analyze_pcap: ${err.message}`);
			return {
				content: [{ type: "text", text: `Error: ${err.message}` }],
				isError: true,
			};
		}
	}

	// TOOL 7: extract_credentials
	if (name === "extract_credentials") {
		try {
			const tsharkPath = await findTshark();
			const { pcapPath } = args;
			console.log(`Extracting credentials from PCAP file: ${pcapPath}`);

			await fs.access(pcapPath);

			const { stdout: plaintextOut } = await execAsync(
				`${tsharkPath} -r "${pcapPath}" -T fields -e http.authbasic -e ftp.request.command -e ftp.request.arg -e telnet.data -e frame.number`,
				{
					env: {
						...process.env,
						PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin`,
					},
				},
			);

			const { stdout: kerberosOut } = await execAsync(
				`${tsharkPath} -r "${pcapPath}" -T fields -e kerberos.CNameString -e kerberos.realm -e kerberos.cipher -e kerberos.type -e kerberos.msg_type -e frame.number`,
				{
					env: {
						...process.env,
						PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin`,
					},
				},
			);

			const lines = plaintextOut.split("\n").filter((line) => line.trim());
			const packets = lines.map((line) => {
				const [authBasic, ftpCmd, ftpArg, telnetData, frameNumber] =
					line.split("\t");
				return {
					authBasic: authBasic || "",
					ftpCmd: ftpCmd || "",
					ftpArg: ftpArg || "",
					telnetData: telnetData || "",
					frameNumber: frameNumber || "",
				};
			});

			const credentials: Credentials = {
				plaintext: [],
				encrypted: [],
			};

			// Process HTTP Basic Auth
			packets.forEach((p) => {
				if (p.authBasic) {
					const [username, password] = Buffer.from(p.authBasic, "base64")
						.toString()
						.split(":");
					credentials.plaintext.push({
						type: "HTTP Basic Auth",
						username,
						password,
						frame: p.frameNumber,
					});
				}
			});

			// Process FTP
			packets.forEach((p) => {
				if (p.ftpCmd === "USER") {
					credentials.plaintext.push({
						type: "FTP",
						username: p.ftpArg,
						password: "",
						frame: p.frameNumber,
					});
				}
				if (p.ftpCmd === "PASS") {
					const lastUser = credentials.plaintext.findLast(
						(c: PlaintextCredential) => c.type === "FTP" && !c.password,
					);
					if (lastUser) lastUser.password = p.ftpArg;
				}
			});

			// Process Telnet
			packets.forEach((p) => {
				if (p.telnetData) {
					const telnetStr = p.telnetData.trim();
					if (
						telnetStr.toLowerCase().includes("login:") ||
						telnetStr.toLowerCase().includes("password:")
					) {
						credentials.plaintext.push({
							type: "Telnet Prompt",
							data: telnetStr,
							frame: p.frameNumber,
						});
					} else if (
						telnetStr &&
						!telnetStr.match(/[A-Z][a-z]+:/) &&
						!telnetStr.includes(" ")
					) {
						const lastPrompt = credentials.plaintext.findLast(
							(c: PlaintextCredential) => c.type === "Telnet Prompt",
						);
						if (
							lastPrompt &&
							lastPrompt.data?.toLowerCase().includes("login:")
						) {
							credentials.plaintext.push({
								type: "Telnet",
								username: telnetStr,
								password: "",
								frame: p.frameNumber,
							});
						} else if (
							lastPrompt &&
							lastPrompt.data?.toLowerCase().includes("password:")
						) {
							const lastUser = credentials.plaintext.findLast(
								(c: PlaintextCredential) => c.type === "Telnet" && !c.password,
							);
							if (lastUser) lastUser.password = telnetStr;
							else
								credentials.plaintext.push({
									type: "Telnet",
									username: "",
									password: telnetStr,
									frame: p.frameNumber,
								});
						}
					}
				}
			});

			// Process Kerberos credentials
			const kerberosLines = kerberosOut
				.split("\n")
				.filter((line) => line.trim());
			kerberosLines.forEach((line) => {
				const [cname, realm, cipher, type, msgType, frameNumber] =
					line.split("\t");

				if (cipher && type) {
					let hashFormat = "";
					if (msgType === "10" || msgType === "30") {
						hashFormat = "$krb5pa$23$";
						if (cname) hashFormat += `${cname}$`;
						if (realm) hashFormat += `${realm}$`;
						hashFormat += cipher;
					} else if (msgType === "11") {
						hashFormat = "$krb5asrep$23$";
						if (cname) hashFormat += `${cname}@`;
						if (realm) hashFormat += `${realm}$`;
						hashFormat += cipher;
					}

					if (hashFormat) {
						credentials.encrypted.push({
							type: "Kerberos",
							hash: hashFormat,
							username: cname || "unknown",
							realm: realm || "unknown",
							frame: frameNumber,
							crackingMode:
								msgType === "11" ? "hashcat -m 18200" : "hashcat -m 7500",
						});
					}
				}
			});

			const outputText =
				`Analyzed PCAP: ${pcapPath}\n\n` +
				`Plaintext Credentials:\n${
					credentials.plaintext.length > 0
						? credentials.plaintext
								.map((c) =>
									c.type === "Telnet Prompt"
										? `${c.type}: ${c.data} (Frame ${c.frame})`
										: `${c.type}: ${c.username}:${c.password} (Frame ${c.frame})`,
								)
								.join("\n")
						: "None"
				}\n\n` +
				`Encrypted/Hashed Credentials:\n${
					credentials.encrypted.length > 0
						? credentials.encrypted
								.map(
									(c) =>
										`${c.type}: User=${c.username} Realm=${c.realm} (Frame ${c.frame})\n` +
										`Hash=${c.hash}\n` +
										`Cracking Command: ${c.crackingMode}\n`,
								)
								.join("\n")
						: "None"
				}`;

			return {
				content: [{ type: "text", text: outputText }],
			};
		} catch (error) {
			const err = error as Error;
			console.log(`Error in extract_credentials: ${err.message}`);
			return {
				content: [{ type: "text", text: `Error: ${err.message}` }],
				isError: true,
			};
		}
	}

	throw new Error(`Unknown tool: ${name}`);
}
