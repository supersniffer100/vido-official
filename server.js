const http = require("http");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { randomUUID, scryptSync, timingSafeEqual } = require("crypto");

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, "public");
const DATA_DIR = path.join(ROOT, "data");
const LEGACY_PROFILE_DIR = path.join(DATA_DIR, "profile-pictures");
const LEGACY_VIDEO_DIR = path.join(DATA_DIR, "videos");
const DB_PATH = path.join(DATA_DIR, "db.json");
const PID_PATH = path.join(ROOT, ".vido-server.pid");
const PORT = process.env.PORT || 3000;

// 🚧 MAINTENANCE SWITCH
const MAINTENANCE_MODE = process.env.MAINTENANCE === "true";

const MIME_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".ico": "image/x-icon",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".mp4": "video/mp4",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".txt": "text/plain; charset=utf-8",
    ".webp": "image/webp"
};

const BLOCKED_WORDS = [
    "asshole", "bastard", "bitch", "bullshit", "cocksucker", "cunt", "damn", "dick",
    "douche", "fag", "fuck", "fucker", "goddamn", "hell", "motherfucker", "nigger",
    "piss", "prick", "shit", "slut", "whore"
];

ensureDir(DATA_DIR);
ensureDir(LEGACY_PROFILE_DIR);
ensureDir(LEGACY_VIDEO_DIR);
ensureDb();
migrateDb();
writePidFile();

const server = http.createServer(async (req, res) => {
    try {

        const url = new URL(req.url, `http://${req.headers.host}`);

        // 🚧 MAINTENANCE MODE GATE
        if (MAINTENANCE_MODE) {
            if (url.pathname.startsWith("/api")) {
                return sendJson(res, 503, { error: "Vido is under maintenance." });
            }

            const filePath = path.join(PUBLIC_DIR, "maintenance.html");
            return serveFile(filePath, req, res);
        }

        // =========================
        // API ROUTES
        // =========================

        if (req.method === "GET" && url.pathname === "/api/session") {
            const db = readDb();
            const account = getAuthenticatedAccount(req, db);
            if (!account) return sendJson(res, 200, { authenticated: false });
            return sendJson(res, 200, { authenticated: true, profile: sanitizeAccount(account) });
        }

        if (req.method === "POST" && url.pathname === "/api/signup") {
            const body = await readJsonBody(req);
            const name = typeof body.name === "string" ? body.name.trim() : "";
            const password = typeof body.password === "string" ? body.password : "";

            if (!name) return sendJson(res, 400, { error: "Username is required." });
            if (password.length < 4) return sendJson(res, 400, { error: "Password must be at least 4 characters." });

            const db = readDb();
            if (findAccountByName(db, name)) {
                return sendJson(res, 409, { error: "That username is already taken." });
            }

            const account = createAccount(db, name, password);
            createSessionForAccount(db, account.id, res);
            writeDb(db);
            ensureAccountStructure(account);
            writeAccountReadme(account);

            return sendJson(res, 201, {
                message: "Account created.",
                profile: sanitizeAccount(account)
            });
        }

        if (req.method === "POST" && url.pathname === "/api/login") {
            const body = await readJsonBody(req);
            const name = typeof body.name === "string" ? body.name.trim() : "";
            const password = typeof body.password === "string" ? body.password : "";

            const db = readDb();
            const account = findAccountByName(db, name);

            if (!account || !verifyAccountPassword(account, password)) {
                return sendJson(res, 401, { error: "Incorrect username or password." });
            }

            createSessionForAccount(db, account.id, res);
            writeDb(db);

            return sendJson(res, 200, {
                message: "Logged in.",
                profile: sanitizeAccount(account)
            });
        }

        if (req.method === "POST" && url.pathname === "/api/logout") {
            const db = readDb();
            destroySession(req, db);
            clearSessionCookie(res);
            writeDb(db);
            return sendJson(res, 200, { message: "Logged out." });
        }

        if (req.method === "GET" && url.pathname === "/api/videos") {
            const db = readDb();
            const videos = enrichVideos(db, db.videos)
                .sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));

            return sendJson(res, 200, { videos });
        }

        if (req.method === "POST" && url.pathname === "/api/videos") {
            const body = await readJsonBody(req);
            const title = body.title?.trim();

            const db = readDb();
            const account = getAuthenticatedAccount(req, db);
            if (!account) return sendJson(res, 401, { error: "You must be logged in." });

            const upload = validateBase64File(body, ["video/mp4"]);
            if (!upload.ok) return sendJson(res, 400, { error: upload.error });

            const video = {
                id: randomUUID(),
                title,
                uploaderId: account.id,
                uploadedAt: new Date().toISOString(),
                comments: [],
                views: 0
            };

            db.videos.push(video);
            writeDb(db);

            return sendJson(res, 201, { video });
        }

        // =========================
        // STATIC FILES
        // =========================

        if (req.method === "GET") {
            const requestedPath = url.pathname === "/" ? "/index.html" : url.pathname;
            return serveFile(
                path.join(PUBLIC_DIR, stripLeadingSlash(decodePathname(requestedPath))),
                req,
                res
            );
        }

        sendJson(res, 404, { error: "Not found." });

    } catch (err) {
        console.error(err);
        sendJson(res, 500, { error: "Internal server error." });
    }
});

server.listen(PORT, "0.0.0.0", () => {
    console.log(`Vido running on port ${PORT}`);
});

// =========================
// EVERYTHING BELOW UNCHANGED
// =========================

// (all your helper functions stay exactly the same — no changes made below this line)