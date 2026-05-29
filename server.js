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
  "asshole",
  "bastard",
  "bitch",
  "bullshit",
  "cocksucker",
  "cunt",
  "damn",
  "dick",
  "douche",
  "fag",
  "fuck",
  "fucker",
  "goddamn",
  "hell",
  "motherfucker",
  "nigger",
  "piss",
  "prick",
  "shit",
  "slut",
  "whore"
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
      // 🚧 MAINTENANCE MODE GATE - CHECK FIRST
      if (MAINTENANCE_MODE && req.method === "GET") {
          if (url.pathname.startsWith("/api")) {
              return sendJson(res, 503, { error: "Vido is under maintenance." });
          }
          const filePath = path.join(PUBLIC_DIR, "maintenance.html");
          return serveFile(filePath, req, res);
      }

    if (req.method === "GET" && url.pathname === "/api/session") {
      const db = readDb();
      const account = getAuthenticatedAccount(req, db);
      if (!account) {
        return sendJson(res, 200, { authenticated: false });
      }
      return sendJson(res, 200, { authenticated: true, profile: sanitizeAccount(account) });
    }

    if (req.method === "POST" && url.pathname === "/api/signup") {
      const body = await readJsonBody(req);
      const name = typeof body.name === "string" ? body.name.trim() : "";
      const password = typeof body.password === "string" ? body.password : "";

      if (!name) {
        return sendJson(res, 400, { error: "Username is required." });
      }
      if (password.length < 4) {
        return sendJson(res, 400, { error: "Password must be at least 4 characters." });
      }

      const db = readDb();
      if (findAccountByName(db, name)) {
        return sendJson(res, 409, { error: "That username is already taken." });
      }

      const account = createAccount(db, name, password);
      createSessionForAccount(db, account.id, res);
      writeDb(db);
      ensureAccountStructure(account);
      writeAccountReadme(account);
      logEvent("ACCOUNT_SIGNED_UP", { account: account.name, accountId: account.id });

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

      if (!account) {
        return sendJson(res, 401, { error: "Incorrect username or password." });
      }

      if (!verifyAccountPassword(account, password)) {
        return sendJson(res, 401, { error: "Incorrect username or password." });
      }

      createSessionForAccount(db, account.id, res);
      writeDb(db);
      logEvent("ACCOUNT_LOGGED_IN", { account: account.name, accountId: account.id });

      return sendJson(res, 200, {
        message: "Logged in.",
        profile: sanitizeAccount(account)
      });
    }

    if (req.method === "POST" && url.pathname === "/api/logout") {
      const db = readDb();
      const account = getAuthenticatedAccount(req, db);
      destroySession(req, db);
      clearSessionCookie(res);
      writeDb(db);
      logEvent("ACCOUNT_LOGGED_OUT", {
        account: account ? account.name : "anonymous",
        accountId: account ? account.id : ""
      });
      return sendJson(res, 200, { message: "Logged out." });
    }

    if (req.method === "GET" && url.pathname === "/api/profile") {
      const db = readDb();
      const account = getAuthenticatedAccount(req, db);
      if (!account) {
        return sendJson(res, 401, { error: "You must be logged in." });
      }
      return sendJson(res, 200, sanitizeAccount(account));
    }

    if (req.method === "POST" && url.pathname === "/api/profile/password") {
      const db = readDb();
      const account = getAuthenticatedAccount(req, db);
      if (!account) {
        return sendJson(res, 401, { error: "You must be logged in." });
      }

      const body = await readJsonBody(req);
      const currentPassword = typeof body.currentPassword === "string" ? body.currentPassword : "";
      const newPassword = typeof body.newPassword === "string" ? body.newPassword : "";

      if (newPassword.length < 4) {
        return sendJson(res, 400, { error: "New password must be at least 4 characters." });
      }

      if (account.passwordHash && !verifyAccountPassword(account, currentPassword)) {
        return sendJson(res, 401, { error: "Current password is incorrect." });
      }

      setAccountPassword(account, newPassword);
      writeDb(db);
      logEvent("ACCOUNT_PASSWORD_UPDATED", { account: account.name, accountId: account.id });
      return sendJson(res, 200, { message: "Password updated." });
    }

    if (req.method === "PUT" && url.pathname === "/api/profile") {
      const body = await readJsonBody(req);
      const db = readDb();
      const account = getAuthenticatedAccount(req, db);
      if (!account) {
        return sendJson(res, 401, { error: "You must be logged in." });
      }

      const nextName = typeof body.name === "string" ? body.name.trim() : "";
      if (!nextName) {
        return sendJson(res, 400, { error: "Name is required." });
      }

      const existing = findAccountByName(db, nextName);
      if (existing && existing.id !== account.id) {
        return sendJson(res, 409, { error: "That username is already taken." });
      }

      const previousFolderPath = getAccountDir(account);
      account.name = nextName.slice(0, 40);
      account.folderName = allocateUniqueAccountFolder(db, account.name, account.id);
      const nextFolderPath = getAccountDir(account);

      if (path.normalize(previousFolderPath) !== path.normalize(nextFolderPath) && fs.existsSync(previousFolderPath)) {
        safeMove(previousFolderPath, nextFolderPath);
      }

      ensureDir(nextFolderPath);
      ensureDir(getAccountVideosDir(account));
      refreshAccountPaths(account, db.videos);
      syncAccountFiles(account, db.videos);
      writeAccountReadme(account);
      writeDb(db);
      logEvent("PROFILE_NAME_UPDATED", { account: account.name, accountId: account.id });

      return sendJson(res, 200, sanitizeAccount(account));
    }

    if (req.method === "POST" && url.pathname === "/api/profile-picture") {
      const body = await readJsonBody(req);
      const upload = validateBase64File(body, ["image/jpeg", "image/png", "image/webp"]);

      if (!upload.ok) {
        return sendJson(res, 400, { error: upload.error });
      }

      const db = readDb();
      const account = getAuthenticatedAccount(req, db);
      if (!account) {
        return sendJson(res, 401, { error: "You must be logged in." });
      }

      ensureAccountStructure(account);
      removeExistingProfilePictures(account);

      const extension = mimeToExtension(upload.mimeType);
      const filePath = path.join(getAccountDir(account), `pfp${extension}`);
      fs.writeFileSync(filePath, upload.buffer);
      account.picturePath = toPublicPath(filePath);
      writeAccountReadme(account);

      writeDb(db);
      logEvent("PROFILE_PICTURE_UPDATED", {
        account: account.name,
        accountId: account.id,
        picturePath: account.picturePath
      });
      return sendJson(res, 201, sanitizeAccount(account));
    }

    if (req.method === "GET" && url.pathname.startsWith("/api/profiles/")) {
      const db = readDb();
      const viewer = getAuthenticatedAccount(req, db);
      const profileId = decodeURIComponent(url.pathname.split("/").pop() || "");
      const account = db.accounts.find((entry) => entry.id === profileId);

      if (!account) {
        return sendJson(res, 404, { error: "Profile not found." });
      }

      const videos = enrichVideos(db, db.videos)
        .filter((video) => video.uploaderId === account.id)
        .sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));

      return sendJson(res, 200, {
        profile: sanitizeAccount(account, viewer),
        videos
      });
    }

    if (req.method === "POST" && url.pathname.startsWith("/api/profiles/") && url.pathname.endsWith("/follow")) {
      const db = readDb();
      const viewer = getAuthenticatedAccount(req, db);
      if (!viewer) {
        return sendJson(res, 401, { error: "You must be logged in to follow someone." });
      }

      const parts = url.pathname.split("/");
      const profileId = decodeURIComponent(parts[parts.length - 2] || "");
      const account = db.accounts.find((entry) => entry.id === profileId);

      if (!account) {
        return sendJson(res, 404, { error: "Profile not found." });
      }
      if (account.id === viewer.id) {
        return sendJson(res, 400, { error: "You cannot follow yourself." });
      }
      if (!Array.isArray(account.followerIds)) {
        account.followerIds = [];
      }
      if (!account.followerIds.includes(viewer.id)) {
        account.followerIds.push(viewer.id);
      }

      writeAccountReadme(account);
      writeDb(db);
      logEvent("ACCOUNT_FOLLOWED", {
        account: viewer.name,
        accountId: viewer.id,
        target: account.name,
        targetId: account.id
      });

      return sendJson(res, 200, {
        message: `You are now following ${account.name}.`,
        profile: sanitizeAccount(account, viewer)
      });
    }

    if (req.method === "DELETE" && url.pathname.startsWith("/api/profiles/") && url.pathname.endsWith("/follow")) {
      const db = readDb();
      const viewer = getAuthenticatedAccount(req, db);
      if (!viewer) {
        return sendJson(res, 401, { error: "You must be logged in to unfollow someone." });
      }

      const parts = url.pathname.split("/");
      const profileId = decodeURIComponent(parts[parts.length - 2] || "");
      const account = db.accounts.find((entry) => entry.id === profileId);

      if (!account) {
        return sendJson(res, 404, { error: "Profile not found." });
      }
      if (account.id === viewer.id) {
        return sendJson(res, 400, { error: "You cannot unfollow yourself." });
      }

      account.followerIds = (account.followerIds || []).filter((id) => id !== viewer.id);
      writeAccountReadme(account);
      writeDb(db);
      logEvent("ACCOUNT_UNFOLLOWED", {
        account: viewer.name,
        accountId: viewer.id,
        target: account.name,
        targetId: account.id
      });

      return sendJson(res, 200, {
        message: `You unfollowed ${account.name}.`,
        profile: sanitizeAccount(account, viewer)
      });
    }

    if (req.method === "GET" && url.pathname === "/api/videos") {
      const db = readDb();
      const query = (url.searchParams.get("q") || "").trim().toLowerCase();
      const videos = enrichVideos(db, db.videos)
        .slice()
        .sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));

      if (query) {
        const filtered = videos.filter((video) => {
          return (
            video.title.toLowerCase().includes(query) ||
            video.originalName.toLowerCase().includes(query) ||
            video.uploaderName.toLowerCase().includes(query)
          );
        });

        return sendJson(res, 200, {
          query,
          videos: filtered,
          total: filtered.length
        });
      }

      const homeVideos = videos.filter((video) => video.showOnHome);
      return sendJson(res, 200, {
        query: "",
        videos: homeVideos,
        total: homeVideos.length
      });
    }

    if (req.method === "POST" && url.pathname === "/api/videos") {
      const body = await readJsonBody(req);
      const title = typeof body.title === "string" ? body.title.trim() : "";
      const upload = validateBase64File(body, ["video/mp4"]);

      if (!title) {
        return sendJson(res, 400, { error: "Title is required." });
      }

      if (!upload.ok) {
        return sendJson(res, 400, { error: upload.error });
      }

      const db = readDb();
      const account = getAuthenticatedAccount(req, db);
      if (!account) {
        return sendJson(res, 401, { error: "You must be logged in." });
      }

      ensureAccountStructure(account);
      const uploadedVideoCount = db.videos.length;
      const originalName = sanitizeFileName(body.fileName || `${title}.mp4`, ".mp4");
      const video = {
        id: randomUUID(),
        title: title.slice(0, 100),
        originalName,
        uploadedAt: new Date().toISOString(),
        showOnHome: uploadedVideoCount < 100,
        uploaderId: account.id,
        folderName: allocateUniqueVideoFolder(db, account.id, title),
        views: 0
      };

      const videoDir = getVideoDir(account, video);
      const filePath = path.join(videoDir, originalName);
      ensureDir(videoDir);
      fs.writeFileSync(filePath, upload.buffer);

      video.url = toPublicPath(filePath);
      video.detailsPath = toPublicPath(path.join(videoDir, "details.txt"));
      writeVideoDetails(account, video);

      db.videos.push(video);
      writeDb(db);
      logEvent("VIDEO_UPLOADED", {
        account: account.name,
        accountId: account.id,
        title: video.title,
        videoId: video.id
      });

      return sendJson(res, 201, {
        video: enrichVideo(db, video),
        message: video.showOnHome
          ? "Video uploaded and added to the home page."
          : "Video uploaded. It is searchable, but hidden from the home page because the first 100 slots are full."
      });
    }

    if (req.method === "DELETE" && url.pathname.startsWith("/api/videos/")) {
      const db = readDb();
      const currentAccount = getAuthenticatedAccount(req, db);
      if (!currentAccount) {
        return sendJson(res, 401, { error: "You must be logged in." });
      }

      const videoId = decodeURIComponent(url.pathname.split("/").pop() || "");
      const videoIndex = db.videos.findIndex((video) => video.id === videoId);

      if (videoIndex === -1) {
        return sendJson(res, 404, { error: "Video not found." });
      }

      const video = db.videos[videoIndex];
      if (video.uploaderId !== currentAccount.id) {
        return sendJson(res, 403, { error: "You can only delete your own videos." });
      }

      safeRemoveDir(getVideoDir(currentAccount, video));
      db.videos.splice(videoIndex, 1);
      writeDb(db);
      logEvent("VIDEO_DELETED", {
        account: currentAccount.name,
        accountId: currentAccount.id,
        title: video.title,
        videoId: video.id
      });

      return sendJson(res, 200, { message: "Video deleted." });
    }

    if (req.method === "POST" && url.pathname.startsWith("/api/videos/") && url.pathname.endsWith("/view")) {
      const db = readDb();
      const parts = url.pathname.split("/");
      const videoId = decodeURIComponent(parts[parts.length - 2] || "");
      const video = db.videos.find((entry) => entry.id === videoId);

      if (!video) {
        return sendJson(res, 404, { error: "Video not found." });
      }

      const account = db.accounts.find((entry) => entry.id === video.uploaderId) || db.accounts[0];
      video.views = Number(video.views || 0) + 1;
      writeVideoDetails(account, video);
      writeDb(db);
      logEvent("VIDEO_VIEWED", {
        account: account.name,
        accountId: account.id,
        title: video.title,
        videoId: video.id,
        views: video.views
      });

      return sendJson(res, 200, {
        message: "View recorded.",
        video: enrichVideo(db, video)
      });
    }

    if (req.method === "GET" && url.pathname.startsWith("/api/videos/") && url.pathname.endsWith("/comments")) {
      const db = readDb();
      const parts = url.pathname.split("/");
      const videoId = decodeURIComponent(parts[parts.length - 2] || "");
      const video = db.videos.find((entry) => entry.id === videoId);

      if (!video) {
        return sendJson(res, 404, { error: "Video not found." });
      }

      return sendJson(res, 200, {
        comments: enrichComments(db, video.comments || [])
      });
    }

    if (req.method === "POST" && url.pathname.startsWith("/api/videos/") && url.pathname.endsWith("/comments")) {
      const db = readDb();
      const author = getAuthenticatedAccount(req, db);
      if (!author) {
        return sendJson(res, 401, { error: "You must be logged in to post a comment." });
      }

      const parts = url.pathname.split("/");
      const videoId = decodeURIComponent(parts[parts.length - 2] || "");
      const video = db.videos.find((entry) => entry.id === videoId);

      if (!video) {
        return sendJson(res, 404, { error: "Video not found." });
      }

      const body = await readJsonBody(req);
      const text = typeof body.text === "string" ? body.text.trim() : "";

      if (!text) {
        return sendJson(res, 400, { error: "Comment text is required." });
      }
      if (text.length > 500) {
        return sendJson(res, 400, { error: "Comments must be 500 characters or less." });
      }
      if (containsBlockedWord(text)) {
        return sendJson(res, 400, { error: "That comment contains blocked language." });
      }

      if (!Array.isArray(video.comments)) {
        video.comments = [];
      }

      const comment = {
        id: randomUUID(),
        authorId: author.id,
        text,
        createdAt: new Date().toISOString()
      };

      video.comments.push(comment);
      writeDb(db);
      logEvent("VIDEO_COMMENT_POSTED", {
        account: author.name,
        accountId: author.id,
        videoId: video.id,
        commentId: comment.id
      });

      return sendJson(res, 201, {
        message: "Comment posted.",
        comment: enrichComment(db, comment)
      });
    }

    if ((req.method === "GET" || req.method === "HEAD") && url.pathname.startsWith("/data/")) {
      return serveFile(path.join(ROOT, stripLeadingSlash(decodePathname(url.pathname))), req, res);
    }

    if (req.method === "GET" || req.method === "HEAD") {
      const requestedPath = url.pathname === "/" ? "/index.html" : url.pathname;
      return serveFile(path.join(PUBLIC_DIR, stripLeadingSlash(decodePathname(requestedPath))), req, res);
    }

    sendJson(res, 404, { error: "Not found." });
  } catch (error) {
    console.error(error);
    sendJson(res, 500, { error: "Internal server error." });
  }
});

server.listen(PORT, "0.0.0.0", () => {
  const ip = getLocalIp();

  logEvent("SERVER_STARTED", {
    port: PORT,
    pid: process.pid,
    ip
  });

  console.log(`Vido is running locally: http://localhost:${PORT}`);
  console.log(`Vido on Wi-Fi: http://${ip}:${PORT}`);
});

function getLocalIp() {
  const nets = os.networkInterfaces();

  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === "IPv4" && !net.internal) {
        return net.address;
      }
    }
  }

  return "localhost";
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
process.on("exit", removePidFile);

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function ensureDb() {
  if (!fs.existsSync(DB_PATH)) {
    const accountId = randomUUID();
    const initialDb = {
      currentAccountId: accountId,
      accounts: [
        {
          id: accountId,
          name: "Vido Creator",
          folderName: "vido-creator",
          picturePath: "",
          passwordHash: "",
          passwordSalt: "",
          followerIds: []
        }
      ],
      sessions: [],
      videos: []
    };
    fs.writeFileSync(DB_PATH, JSON.stringify(initialDb, null, 2));
  }
}

function migrateDb() {
  const db = readDb();

  if (!Array.isArray(db.accounts)) {
    const accountId = randomUUID();
    db.currentAccountId = accountId;
    db.accounts = [
      {
        id: accountId,
        name: db.profile?.name || "Vido Creator",
        folderName: sanitizeSegment(db.profile?.name || "Vido Creator", "vido-creator"),
        picturePath: db.profile?.picturePath || "",
        passwordHash: "",
        passwordSalt: "",
        followerIds: []
      }
    ];
    delete db.profile;
  }

  if (!Array.isArray(db.sessions)) {
    db.sessions = [];
  }

  if (!db.currentAccountId && db.accounts[0]) {
    db.currentAccountId = db.accounts[0].id;
  }

  for (const account of db.accounts) {
    if (!account.id) {
      account.id = randomUUID();
    }
    if (typeof account.name !== "string" || !account.name.trim()) {
      account.name = "Vido Creator";
    }
    if (typeof account.folderName !== "string" || !account.folderName.trim()) {
      account.folderName = allocateUniqueAccountFolder(db, account.name, account.id);
    }
    if (typeof account.picturePath !== "string") {
      account.picturePath = "";
    }
    if (typeof account.passwordHash !== "string") {
      account.passwordHash = "";
    }
    if (typeof account.passwordSalt !== "string") {
      account.passwordSalt = "";
    }
    if (!Array.isArray(account.followerIds)) {
      account.followerIds = [];
    }

    ensureAccountStructure(account);
    migrateProfilePicture(account);
    writeAccountReadme(account);
  }

  for (const video of db.videos) {
    if (!video.id) {
      video.id = randomUUID();
    }
    if (!video.uploaderId) {
      video.uploaderId = db.currentAccountId;
    }
    if (!video.originalName) {
      video.originalName = `${video.title || "video"}.mp4`;
    }
    video.originalName = sanitizeFileName(video.originalName, ".mp4");
    video.views = Number.isFinite(Number(video.views)) ? Number(video.views) : 0;
    if (!Array.isArray(video.comments)) {
      video.comments = [];
    }
  }

  for (const video of db.videos) {
    const account = db.accounts.find((entry) => entry.id === video.uploaderId) || db.accounts[0];
    if (!video.folderName || !video.folderName.trim()) {
      video.folderName = allocateUniqueVideoFolder(db, account.id, video.title || video.originalName, video.id);
    }
    migrateVideoStorage(account, video);
    syncVideoFromDetails(account, video);
    writeVideoDetails(account, video);
  }

  writeDb(db);
}

function readDb() {
  return JSON.parse(fs.readFileSync(DB_PATH, "utf-8"));
}

function writeDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

function sanitizeAccount(account, viewer = null) {
  const followerIds = Array.isArray(account.followerIds) ? account.followerIds : [];
  return {
    id: account.id,
    name: account.name,
    picturePath: account.picturePath,
    folderName: account.folderName,
    followerCount: followerIds.length,
    isFollowedByViewer: Boolean(viewer && followerIds.includes(viewer.id)),
    canFollow: Boolean(viewer && viewer.id !== account.id)
  };
}

function findAccountByName(db, name) {
  const normalized = String(name || "").trim().toLowerCase();
  return db.accounts.find((account) => account.name.toLowerCase() === normalized) || null;
}

function createAccount(db, name, password) {
  const account = {
    id: randomUUID(),
    name: name.slice(0, 40),
    folderName: allocateUniqueAccountFolder(db, name, ""),
    picturePath: "",
    passwordHash: "",
    passwordSalt: "",
    followerIds: []
  };
  setAccountPassword(account, password);
  db.accounts.push(account);
  return account;
}

function setAccountPassword(account, password) {
  const salt = randomUUID();
  account.passwordSalt = salt;
  account.passwordHash = scryptSync(password, salt, 64).toString("hex");
}

function verifyAccountPassword(account, password) {
  if (!account.passwordHash || !account.passwordSalt) {
    return password === "";
  }

  const expected = Buffer.from(account.passwordHash, "hex");
  const actual = scryptSync(password, account.passwordSalt, 64);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

function getAuthenticatedAccount(req, db) {
  const sessionId = parseCookies(req).vido_session;
  if (!sessionId) {
    return null;
  }
  const session = db.sessions.find((entry) => entry.id === sessionId);
  if (!session) {
    return null;
  }
  return db.accounts.find((account) => account.id === session.accountId) || null;
}

function createSessionForAccount(db, accountId, res) {
  const session = {
    id: randomUUID(),
    accountId,
    createdAt: new Date().toISOString()
  };
  db.sessions = db.sessions.filter((entry) => entry.accountId !== accountId);
  db.sessions.push(session);
  setSessionCookie(res, session.id);
}

function destroySession(req, db) {
  const sessionId = parseCookies(req).vido_session;
  if (!sessionId) {
    return;
  }
  db.sessions = db.sessions.filter((entry) => entry.id !== sessionId);
}

function parseCookies(req) {
  const raw = req.headers.cookie || "";
  const cookies = {};
  for (const part of raw.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (!name) continue;
    cookies[name] = decodeURIComponent(rest.join("="));
  }
  return cookies;
}

function setSessionCookie(res, sessionId) {
  res.setHeader("Set-Cookie", `vido_session=${encodeURIComponent(sessionId)}; HttpOnly; Path=/; SameSite=Lax`);
}

function clearSessionCookie(res) {
  res.setHeader("Set-Cookie", "vido_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax");
}

function enrichVideos(db, videos) {
  return videos.map((video) => enrichVideo(db, video));
}

function enrichVideo(db, video) {
  const account = db.accounts.find((entry) => entry.id === video.uploaderId) || db.accounts[0];
  return {
    ...video,
    views: Number(video.views || 0),
    comments: enrichComments(db, video.comments || []),
    uploaderId: account.id,
    uploaderName: account.name,
    uploaderPicturePath: account.picturePath
  };
}

function enrichComments(db, comments) {
  return comments.map((comment) => enrichComment(db, comment));
}

function enrichComment(db, comment) {
  const author = db.accounts.find((entry) => entry.id === comment.authorId);
  return {
    ...comment,
    authorName: author ? author.name : "Unknown user"
  };
}

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(payload));
}

function writePidFile() {
  fs.writeFileSync(PID_PATH, String(process.pid));
}

function removePidFile() {
  if (fs.existsSync(PID_PATH)) {
    const current = fs.readFileSync(PID_PATH, "utf-8").trim();
    if (current === String(process.pid)) {
      fs.unlinkSync(PID_PATH);
    }
  }
}

function shutdown() {
  logEvent("SERVER_STOPPED", { port: PORT, pid: process.pid });
  removePidFile();
  process.exit(0);
}

function logEvent(type, details) {
  const timestamp = new Date().toISOString();
  const pairs = Object.entries(details || {})
    .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
    .join(" ");
  console.log(`[${timestamp}] ${type}${pairs ? ` ${pairs}` : ""}`);
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > 250 * 1024 * 1024) {
        reject(new Error("Request body too large."));
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch (error) {
        reject(new Error("Invalid JSON body."));
      }
    });
    req.on("error", reject);
  });
}

function validateBase64File(body, allowedMimeTypes) {
  if (!body || typeof body.data !== "string" || typeof body.mimeType !== "string") {
    return { ok: false, error: "Missing file upload data." };
  }
  if (!allowedMimeTypes.includes(body.mimeType)) {
    return { ok: false, error: `Unsupported file type: ${body.mimeType}` };
  }

  try {
    const buffer = Buffer.from(body.data, "base64");
    if (!buffer.length) {
      return { ok: false, error: "Uploaded file was empty." };
    }
    return { ok: true, buffer, mimeType: body.mimeType };
  } catch (error) {
    return { ok: false, error: "Could not decode uploaded file." };
  }
}

function containsBlockedWord(text) {
  const normalized = ` ${String(text || "").toLowerCase()} `;
  return BLOCKED_WORDS.some((word) => normalized.includes(` ${word} `) || normalized.includes(`${word}.`) || normalized.includes(`${word}!`) || normalized.includes(`${word}?`) || normalized.includes(`${word},`));
}

function mimeToExtension(mimeType) {
  if (mimeType === "image/jpeg") return ".jpg";
  if (mimeType === "image/png") return ".png";
  if (mimeType === "image/webp") return ".webp";
  return "";
}

function toPublicPath(filePath) {
  return path.relative(ROOT, filePath).split(path.sep).join("/");
}

function stripLeadingSlash(value) {
  return value.replace(/^[/\\]+/, "");
}

function decodePathname(value) {
  try {
    return decodeURIComponent(value);
  } catch (error) {
    return value;
  }
}

function serveFile(filePath, req, res) {
  const normalizedPath = path.normalize(filePath);
  if (!normalizedPath.startsWith(ROOT)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }

  fs.stat(normalizedPath, (statError, stats) => {
    if (statError || !stats.isFile()) {
      res.writeHead(404);
      res.end("Not found");
      return;
    }

    const extension = path.extname(normalizedPath).toLowerCase();
    const contentType = MIME_TYPES[extension] || "application/octet-stream";
    const rangeHeader = req.headers.range;

    if (rangeHeader) {
      const match = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader);
      if (!match) {
        res.writeHead(416, { "Content-Range": `bytes */${stats.size}` });
        res.end();
        return;
      }

      let start = match[1] ? Number(match[1]) : 0;
      let end = match[2] ? Number(match[2]) : stats.size - 1;
      if (!Number.isFinite(start) || !Number.isFinite(end) || start > end || start >= stats.size) {
        res.writeHead(416, { "Content-Range": `bytes */${stats.size}` });
        res.end();
        return;
      }

      end = Math.min(end, stats.size - 1);
      res.writeHead(206, {
        "Accept-Ranges": "bytes",
        "Content-Length": end - start + 1,
        "Content-Range": `bytes ${start}-${end}/${stats.size}`,
        "Content-Type": contentType
      });

      if (req.method === "HEAD") {
        res.end();
        return;
      }

      fs.createReadStream(normalizedPath, { start, end }).pipe(res);
      return;
    }

    res.writeHead(200, {
      "Accept-Ranges": "bytes",
      "Content-Length": stats.size,
      "Content-Type": contentType
    });

    if (req.method === "HEAD") {
      res.end();
      return;
    }

    fs.createReadStream(normalizedPath).pipe(res);
  });
}

function sanitizeSegment(value, fallback) {
  const cleaned = String(value || "")
    .toLowerCase()
    .replace(/[<>:"/\\|?*\x00-\x1f]/g, "")
    .replace(/\s+/g, "-")
    .replace(/\.+$/g, "")
    .replace(/^-+|-+$/g, "")
    .replace(/[^a-z0-9-_]/g, "-")
    .replace(/-+/g, "-");
  return cleaned || fallback;
}

function sanitizeFileName(value, fallbackExtension = "") {
  const parsed = path.parse(String(value || ""));
  const baseName = parsed.name.replace(/[<>:"/\\|?*\x00-\x1f]/g, "").trim();
  const extension = parsed.ext || fallbackExtension;
  const safeBase = baseName || "video";
  return `${safeBase}${extension}`;
}

function allocateUniqueAccountFolder(db, accountName, accountId) {
  const base = sanitizeSegment(accountName, "account");
  let candidate = base;
  let index = 2;
  while (db.accounts.some((account) => account.id !== accountId && account.folderName === candidate)) {
    candidate = `${base}-${index}`;
    index += 1;
  }
  return candidate;
}

function allocateUniqueVideoFolder(db, uploaderId, title, excludeVideoId = "") {
  const base = sanitizeSegment(title, "video");
  let candidate = base;
  let index = 2;
  while (
    db.videos.some(
      (video) =>
        video.id !== excludeVideoId &&
        video.uploaderId === uploaderId &&
        video.folderName === candidate
    )
  ) {
    candidate = `${base}-${index}`;
    index += 1;
  }
  return candidate;
}

function getAccountDir(account) {
  return path.join(DATA_DIR, account.folderName);
}

function getAccountVideosDir(account) {
  return path.join(getAccountDir(account), "videos");
}

function getVideoDir(account, video) {
  return path.join(getAccountVideosDir(account), video.folderName);
}

function ensureAccountStructure(account) {
  ensureDir(getAccountDir(account));
  ensureDir(getAccountVideosDir(account));
}

function refreshAccountPaths(account, videos) {
  if (account.picturePath) {
    const ext = path.extname(account.picturePath) || ".png";
    account.picturePath = toPublicPath(path.join(getAccountDir(account), `pfp${ext}`));
  }

  for (const video of videos.filter((entry) => entry.uploaderId === account.id)) {
    video.url = toPublicPath(path.join(getVideoDir(account, video), video.originalName));
    video.detailsPath = toPublicPath(path.join(getVideoDir(account, video), "details.txt"));
  }
}

function syncAccountFiles(account, videos) {
  if (account.picturePath) {
    const picturePath = path.join(ROOT, account.picturePath);
    if (!fs.existsSync(picturePath)) {
      const existing = findExistingProfilePicture(account);
      if (existing) {
        account.picturePath = toPublicPath(existing);
      }
    }
  }

  for (const video of videos.filter((entry) => entry.uploaderId === account.id)) {
    ensureDir(getVideoDir(account, video));
    writeVideoDetails(account, video);
  }
}

function removeExistingProfilePictures(account) {
  for (const extension of [".jpg", ".png", ".webp"]) {
    const picturePath = path.join(getAccountDir(account), `pfp${extension}`);
    if (fs.existsSync(picturePath)) {
      fs.unlinkSync(picturePath);
    }
  }
}

function findExistingProfilePicture(account) {
  for (const extension of [".jpg", ".png", ".webp"]) {
    const picturePath = path.join(getAccountDir(account), `pfp${extension}`);
    if (fs.existsSync(picturePath)) {
      return picturePath;
    }
  }
  return null;
}

function migrateProfilePicture(account) {
  if (!account.picturePath) {
    return;
  }

  const sourcePath = path.join(ROOT, account.picturePath);
  if (!fs.existsSync(sourcePath)) {
    const existing = findExistingProfilePicture(account);
    account.picturePath = existing ? toPublicPath(existing) : "";
    return;
  }

  const extension = path.extname(sourcePath) || ".png";
  const targetPath = path.join(getAccountDir(account), `pfp${extension}`);
  if (path.normalize(sourcePath) !== path.normalize(targetPath)) {
    removeExistingProfilePictures(account);
    safeMove(sourcePath, targetPath);
  }
  account.picturePath = toPublicPath(targetPath);
}

function migrateVideoStorage(account, video) {
  ensureAccountStructure(account);
  const videoDir = getVideoDir(account, video);
  ensureDir(videoDir);

  const sourcePath = video.url ? path.join(ROOT, video.url) : "";
  const targetPath = path.join(videoDir, video.originalName);
  if (sourcePath && fs.existsSync(sourcePath) && path.normalize(sourcePath) !== path.normalize(targetPath)) {
    safeMove(sourcePath, targetPath);
  }

  video.url = toPublicPath(targetPath);
  video.detailsPath = toPublicPath(path.join(videoDir, "details.txt"));
}

function syncVideoFromDetails(account, video) {
  const detailsPath = path.join(getVideoDir(account, video), "details.txt");
  if (!fs.existsSync(detailsPath)) {
    return;
  }

  const details = fs.readFileSync(detailsPath, "utf-8");
  const parsedViews = readDetailNumber(details, "Views");
  if (parsedViews !== null) {
    video.views = parsedViews;
  }
}

function writeVideoDetails(account, video) {
  const details = [
    `Title: ${video.title}`,
    `Uploader: ${account.name}`,
    `Uploaded At: ${video.uploadedAt}`,
    `Views: ${Number(video.views || 0)}`,
    `Original Filename: ${video.originalName}`,
    `Visible On Home Page: ${video.showOnHome ? "Yes" : "No"}`,
    `Video ID: ${video.id}`
  ].join("\n");

  fs.writeFileSync(path.join(getVideoDir(account, video), "details.txt"), details);
  video.detailsPath = toPublicPath(path.join(getVideoDir(account, video), "details.txt"));
}

function writeAccountReadme(account) {
  const readmePath = path.join(getAccountDir(account), "account.txt");
  const contents = [
    `Username: ${account.name}`,
    `Account ID: ${account.id}`,
    `Profile Picture: ${account.picturePath ? path.basename(account.picturePath) : "None"}`,
    `Followers: ${Array.isArray(account.followerIds) ? account.followerIds.length : 0}`
  ].join("\n");
  fs.writeFileSync(readmePath, contents);
}

function readDetailNumber(detailsText, label) {
  const pattern = new RegExp(`^${escapeRegExp(label)}:\\s*(\\d+)\\s*$`, "mi");
  const match = detailsText.match(pattern);
  return match ? Number(match[1]) : null;
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function safeMove(sourcePath, targetPath) {
  ensureDir(path.dirname(targetPath));
  if (path.normalize(sourcePath) === path.normalize(targetPath)) {
    return;
  }
  if (fs.existsSync(targetPath)) {
    fs.rmSync(targetPath, { recursive: true, force: true });
  }
  fs.renameSync(sourcePath, targetPath);
}

function safeRemoveDir(targetPath) {
  if (fs.existsSync(targetPath)) {
    fs.rmSync(targetPath, { recursive: true, force: true });
  }
}
