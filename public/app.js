const signedInPanel = document.getElementById("signed-in-panel");
const signedOutPanel = document.getElementById("signed-out-panel");
const profileName = document.getElementById("profile-name");
const profilePicture = document.getElementById("profile-picture");
const displayNameInput = document.getElementById("display-name");
const uploadCopy = document.getElementById("upload-copy");
const statusBox = document.getElementById("status");
const videoGrid = document.getElementById("video-grid");
const emptyState = document.getElementById("empty-state");
const sectionTitle = document.getElementById("section-title");
const sectionCopy = document.getElementById("section-copy");
const videoTemplate = document.getElementById("video-card-template");
const searchInput = document.getElementById("search-input");
const watchDialog = document.getElementById("watch-dialog");
const dialogVideo = document.getElementById("dialog-video");
const dialogTitle = document.getElementById("dialog-title");
const dialogMeta = document.getElementById("dialog-meta");
const dialogUploader = document.getElementById("dialog-uploader");
const commentsTitle = document.getElementById("comments-title");
const commentsCopy = document.getElementById("comments-copy");
const commentForm = document.getElementById("comment-form");
const commentInput = document.getElementById("comment-input");
const commentLoginNote = document.getElementById("comment-login-note");
const commentsList = document.getElementById("comments-list");
const commentsEmpty = document.getElementById("comments-empty");
const profileDialog = document.getElementById("profile-dialog");
const creatorPicture = document.getElementById("creator-picture");
const creatorName = document.getElementById("creator-name");
const creatorFollowers = document.getElementById("creator-followers");
const followButton = document.getElementById("follow-button");
const creatorVideoGrid = document.getElementById("creator-video-grid");
const creatorEmptyState = document.getElementById("creator-empty-state");
const videoForm = document.getElementById("video-form");
const uploadPanel = document.querySelector(".upload-panel");
let currentProfile = null;
let currentQuery = "";
let activeCreatorProfileId = "";
let activeVideo = null;

document.getElementById("login-form").addEventListener("submit", handleLoginSubmit);
document.getElementById("signup-form").addEventListener("submit", handleSignupSubmit);
document.getElementById("logout-button").addEventListener("click", handleLogout);
document.getElementById("password-form").addEventListener("submit", handlePasswordSubmit);
document.getElementById("name-form").addEventListener("submit", handleNameSubmit);
document.getElementById("picture-form").addEventListener("submit", handlePictureSubmit);
document.getElementById("video-form").addEventListener("submit", handleVideoSubmit);
document.getElementById("search-form").addEventListener("submit", handleSearchSubmit);
document.getElementById("close-dialog").addEventListener("click", closeVideoDialog);
document.getElementById("close-profile-dialog").addEventListener("click", closeProfileDialog);
commentForm.addEventListener("submit", handleCommentSubmit);

watchDialog.addEventListener("close", () => {
  dialogVideo.pause();
  dialogVideo.removeAttribute("src");
  dialogVideo.load();
});

loadInitialState();

async function loadInitialState() {
  await Promise.all([loadSession(), loadVideos()]);
}

async function loadSession() {
  const response = await fetch("/api/session");
  const payload = await response.json();
  currentProfile = payload.authenticated ? payload.profile : null;
  renderAuthState();
}

function renderAuthState() {
  signedInPanel.classList.toggle("hidden", !currentProfile);
  signedOutPanel.classList.toggle("hidden", Boolean(currentProfile));
  uploadPanel.classList.toggle("is-disabled", !currentProfile);

  if (currentProfile) {
    profileName.textContent = currentProfile.name;
    displayNameInput.value = currentProfile.name;
    profilePicture.src = currentProfile.picturePath
      ? toAssetUrl(currentProfile.picturePath)
      : createAvatarPlaceholder(currentProfile.name);
    uploadCopy.textContent =
      "Upload an MP4 and it will appear on the home page until the first 100 visible slots are filled.";
    enableForm(videoForm, true);
    commentForm.classList.remove("hidden");
    commentLoginNote.classList.add("hidden");
    enableForm(commentForm, true);
    return;
  }

  uploadCopy.textContent = "Sign in to upload videos, edit your profile, and delete your own uploads.";
  enableForm(videoForm, false);
  commentForm.classList.add("hidden");
  commentLoginNote.classList.remove("hidden");
}

async function handleLoginSubmit(event) {
  event.preventDefault();
  const name = document.getElementById("login-name").value.trim();
  const password = document.getElementById("login-password").value;
  const response = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, password })
  });
  const payload = await response.json();

  if (!response.ok) {
    setStatus(payload.error || "Could not log in.");
    return;
  }

  document.getElementById("login-form").reset();
  currentProfile = payload.profile;
  renderAuthState();
  setStatus(`Logged in as ${payload.profile.name}.`);
}

async function handleSignupSubmit(event) {
  event.preventDefault();
  const name = document.getElementById("signup-name").value.trim();
  const password = document.getElementById("signup-password").value;
  const response = await fetch("/api/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, password })
  });
  const payload = await response.json();

  if (!response.ok) {
    setStatus(payload.error || "Could not create account.");
    return;
  }

  document.getElementById("signup-form").reset();
  currentProfile = payload.profile;
  renderAuthState();
  setStatus(`Account created for ${payload.profile.name}.`);
}

async function handleLogout() {
  await fetch("/api/logout", { method: "POST" });
  currentProfile = null;
  renderAuthState();
  setStatus("Logged out.");
}

async function handlePasswordSubmit(event) {
  event.preventDefault();
  const currentPassword = document.getElementById("current-password").value;
  const newPassword = document.getElementById("new-password").value;
  const response = await fetch("/api/profile/password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ currentPassword, newPassword })
  });
  const payload = await response.json();

  if (!response.ok) {
    setStatus(payload.error || "Could not save password.");
    return;
  }

  event.target.reset();
  setStatus("Password saved.");
}

async function loadVideos(query = "") {
  currentQuery = query;
  const endpoint = query ? `/api/videos?q=${encodeURIComponent(query)}` : "/api/videos";
  const response = await fetch(endpoint);
  const payload = await response.json();

  sectionTitle.textContent = query ? `Search results for "${query}"` : "Main menu videos";
  sectionCopy.textContent = query
    ? "Searching across all uploaded videos, including ones hidden from the home page after the first 100 uploads."
    : "Showing videos visible on the home page.";

  renderVideos(payload.videos || []);
}

async function handleNameSubmit(event) {
  event.preventDefault();
  const response = await fetch("/api/profile", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: displayNameInput.value })
  });
  const payload = await response.json();

  if (!response.ok) {
    setStatus(payload.error || "Could not save your name.");
    return;
  }

  currentProfile = payload;
  renderAuthState();
  setStatus("Display name updated.");
}

async function handlePictureSubmit(event) {
  event.preventDefault();
  const file = document.getElementById("picture-input").files[0];

  if (!file) {
    setStatus("Choose a profile picture first.");
    return;
  }

  const payload = await buildFilePayload(file);
  const response = await fetch("/api/profile-picture", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const data = await response.json();

  if (!response.ok) {
    setStatus(data.error || "Could not upload picture.");
    return;
  }

  currentProfile = data;
  renderAuthState();
  setStatus("Profile picture uploaded.");
  event.target.reset();
}

async function handleVideoSubmit(event) {
  event.preventDefault();
  const titleInput = document.getElementById("video-title");
  const file = document.getElementById("video-input").files[0];

  if (!currentProfile) {
    setStatus("Log in to upload a video.");
    return;
  }

  if (!file) {
    setStatus("Choose an MP4 file first.");
    return;
  }

  const payload = await buildFilePayload(file);
  payload.title = titleInput.value.trim();

  const response = await fetch("/api/videos", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const data = await response.json();

  if (!response.ok) {
    setStatus(data.error || "Could not upload video.");
    return;
  }

  setStatus(data.message);
  titleInput.value = "";
  event.target.reset();
  searchInput.value = "";
  await loadVideos();
}

async function handleSearchSubmit(event) {
  event.preventDefault();
  const query = searchInput.value.trim();
  await loadVideos(query);
  setStatus(query ? `Showing search results for "${query}".` : "Showing home page videos.");
}

function renderVideos(videos) {
  videoGrid.replaceChildren();
  emptyState.hidden = videos.length > 0;

  for (const video of videos) {
    videoGrid.appendChild(buildVideoCard(video));
  }
}

function buildVideoCard(video, options = {}) {
  const { uploaderClickable = true, onOpen = () => openVideoDialog(video) } = options;
  const fragment = videoTemplate.content.cloneNode(true);
  const card = fragment.querySelector(".video-card");
  const title = fragment.querySelector("h3");
  const deleteButton = fragment.querySelector(".delete-button");
  const uploaderLink = fragment.querySelector(".uploader-link");
  const date = fragment.querySelector(".video-date");
  const tag = fragment.querySelector(".video-tag");

  title.textContent = video.title;
  uploaderLink.textContent = video.uploaderName;

  if (uploaderClickable) {
    uploaderLink.addEventListener("click", (event) => {
      event.stopPropagation();
      openProfileDialog(video.uploaderId);
    });
  } else {
    uploaderLink.replaceWith(createStaticMeta(video.uploaderName));
  }

  date.textContent = `${new Date(video.uploadedAt).toLocaleString()} - ${formatViews(video.views)}`;
  tag.textContent = video.showOnHome ? "Visible on home page" : "Search only";

  if (currentProfile && video.uploaderId === currentProfile.id) {
    deleteButton.hidden = false;
    deleteButton.addEventListener("click", async (event) => {
      event.stopPropagation();
      await deleteVideo(video);
    });
  }

  card.dataset.videoId = video.id;
  card.addEventListener("click", onOpen);
  card.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onOpen();
    }
  });

  return fragment;
}

function setStatus(message) {
  statusBox.textContent = message;
}

async function openVideoDialog(video) {
  const viewedVideo = await recordView(video);
  dialogTitle.textContent = viewedVideo.title;
  dialogUploader.textContent = viewedVideo.uploaderName;
  dialogUploader.onclick = () => openProfileDialog(viewedVideo.uploaderId);
  dialogMeta.textContent = `${new Date(viewedVideo.uploadedAt).toLocaleString()} - ${formatViews(viewedVideo.views)} - ${
    viewedVideo.showOnHome ? "Visible on home page" : "Search only"
  }`;
  dialogVideo.src = toAssetUrl(viewedVideo.url);
  dialogVideo.load();
  activeVideo = viewedVideo;
  watchDialog.showModal();
  await loadComments(viewedVideo.id);
  await loadVideos(currentQuery);

  if (profileDialog.open && activeCreatorProfileId) {
    await openProfileDialog(activeCreatorProfileId);
  }
}

function closeVideoDialog() {
  activeVideo = null;
  watchDialog.close();
}

async function openProfileDialog(profileId) {
  const response = await fetch(`/api/profiles/${encodeURIComponent(profileId)}`);
  const payload = await response.json();

  if (!response.ok) {
    setStatus(payload.error || "Could not load that profile.");
    return;
  }

  activeCreatorProfileId = profileId;
  creatorName.textContent = payload.profile.name;
  creatorFollowers.textContent = formatFollowers(payload.profile.followerCount);
  creatorPicture.src = payload.profile.picturePath
    ? toAssetUrl(payload.profile.picturePath)
    : createAvatarPlaceholder(payload.profile.name);

  renderFollowButton(payload.profile);

  creatorVideoGrid.replaceChildren();
  creatorEmptyState.hidden = payload.videos.length > 0;

  for (const video of payload.videos) {
    const fragment = buildVideoCard(video, {
      uploaderClickable: false,
      onOpen: () => {
        if (watchDialog.open) closeVideoDialog();
        closeProfileDialog();
        openVideoDialog(video);
      }
    });
    creatorVideoGrid.appendChild(fragment);
  }

  if (!profileDialog.open) {
    profileDialog.showModal();
  }
}

function closeProfileDialog() {
  activeCreatorProfileId = "";
  profileDialog.close();
}

function renderFollowButton(profile) {
  if (!currentProfile || !profile.canFollow) {
    followButton.classList.add("hidden");
    followButton.onclick = null;
    return;
  }

  followButton.classList.remove("hidden");
  followButton.textContent = profile.isFollowedByViewer ? "Unfollow" : "Follow";
  followButton.onclick = async () => {
    await toggleFollow(profile);
  };
}

async function deleteVideo(video) {
  const confirmed = window.confirm(`Delete "${video.title}"?`);
  if (!confirmed) return;

  const response = await fetch(`/api/videos/${encodeURIComponent(video.id)}`, {
    method: "DELETE"
  });
  const payload = await response.json();

  if (!response.ok) {
    setStatus(payload.error || "Could not delete video.");
    return;
  }

  if (watchDialog.open && dialogTitle.textContent === video.title) {
    closeVideoDialog();
  }

  setStatus(payload.message || "Video deleted.");
  await loadVideos(currentQuery);

  if (profileDialog.open && activeCreatorProfileId) {
    await openProfileDialog(activeCreatorProfileId);
  }
}

function createStaticMeta(text) {
  const element = document.createElement("p");
  element.className = "video-date";
  element.textContent = text;
  return element;
}

function toAssetUrl(assetPath) {
  return `/${encodeURI(String(assetPath).replace(/^[/\\]+/, "").replace(/\\/g, "/"))}`;
}

async function recordView(video) {
  const response = await fetch(`/api/videos/${encodeURIComponent(video.id)}/view`, {
    method: "POST"
  });

  if (!response.ok) {
    return video;
  }

  const payload = await response.json();
  return payload.video || video;
}

function formatViews(views) {
  const count = Number(views || 0);
  return `${count} view${count === 1 ? "" : "s"}`;
}

function formatFollowers(count) {
  const total = Number(count || 0);
  return `${total} follower${total === 1 ? "" : "s"}`;
}

async function toggleFollow(profile) {
  if (!currentProfile) {
    setStatus("You must be signed in to follow someone.");
    return;
  }

  const method = profile.isFollowedByViewer ? "DELETE" : "POST";
  const response = await fetch(`/api/profiles/${encodeURIComponent(profile.id)}/follow`, {
    method
  });
  const payload = await response.json();

  if (!response.ok) {
    setStatus(payload.error || "Could not update follow status.");
    return;
  }

  setStatus(payload.message || "Follow status updated.");
  if (activeCreatorProfileId) {
    await openProfileDialog(activeCreatorProfileId);
  }
}

async function loadComments(videoId) {
  const response = await fetch(`/api/videos/${encodeURIComponent(videoId)}/comments`);
  const payload = await response.json();

  commentsTitle.textContent = `Comments (${payload.comments.length})`;
  commentsCopy.textContent = currentProfile
    ? "Share your thoughts below."
    : "Log in to join the conversation.";

  commentsList.replaceChildren();
  commentsEmpty.hidden = payload.comments.length > 0;

  for (const comment of payload.comments) {
    const card = document.createElement("article");
    card.className = "comment-card";

    const meta = document.createElement("p");
    meta.className = "comment-meta";
    meta.textContent = `${comment.authorName} - ${new Date(comment.createdAt).toLocaleString()}`;

    const body = document.createElement("p");
    body.textContent = comment.text;

    card.append(meta, body);
    commentsList.appendChild(card);
  }
}

async function handleCommentSubmit(event) {
  event.preventDefault();

  if (!currentProfile) {
    setStatus("Log in to post a comment.");
    return;
  }
  if (!activeVideo) {
    setStatus("Open a video before posting a comment.");
    return;
  }

  const text = commentInput.value.trim();
  if (!text) {
    setStatus("Write a comment first.");
    return;
  }

  const response = await fetch(`/api/videos/${encodeURIComponent(activeVideo.id)}/comments`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text })
  });
  const payload = await response.json();

  if (!response.ok) {
    setStatus(payload.error || "Could not post comment.");
    return;
  }

  commentForm.reset();
  setStatus("Comment posted.");
  await loadComments(activeVideo.id);
}

async function buildFilePayload(file) {
  const dataUrl = await readFileAsDataUrl(file);
  const [, meta, base64Data] = dataUrl.match(/^data:(.+);base64,(.+)$/) || [];

  return {
    fileName: file.name,
    mimeType: meta,
    data: base64Data
  };
}

function readFileAsDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(new Error("Failed to read file."));
    reader.readAsDataURL(file);
  });
}

function createAvatarPlaceholder(name) {
  const letter = (name || "V").trim().charAt(0).toUpperCase();
  const svg = `
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120">
      <defs>
        <linearGradient id="g" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop stop-color="#d44d2f" />
          <stop offset="1" stop-color="#f0b35d" />
        </linearGradient>
      </defs>
      <rect width="120" height="120" rx="28" fill="url(#g)" />
      <text x="50%" y="54%" text-anchor="middle" font-size="52" font-family="Georgia, serif" fill="white">${letter}</text>
    </svg>
  `;

  return `data:image/svg+xml;base64,${btoa(svg)}`;
}

function enableForm(form, enabled) {
  for (const element of form.elements) {
    element.disabled = !enabled;
  }
}
