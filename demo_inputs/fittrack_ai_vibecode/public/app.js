window.FITTRACK_CONFIG = {
  apiKey: "fittrack_fake_frontend_key",
  supportEmail: "coach@example.com"
};

console.log("FitTrack AI demo config", window.FITTRACK_CONFIG);

const dashboardMetrics = [
  { label: "Steps", value: "11,842", tone: "teal" },
  { label: "Calories", value: "2,140", tone: "orange" },
  { label: "Sleep Score", value: "87", tone: "violet" },
  { label: "Recovery", value: "Strong", tone: "green" }
];

const workouts = [
  { name: "Upper Body Strength", meta: "42 min · 390 kcal", status: "Completed" },
  { name: "Recovery Run", meta: "28 min · 240 kcal", status: "Scheduled" },
  { name: "Mobility Flow", meta: "18 min · 110 kcal", status: "Completed" }
];

const chartBars = [64, 72, 59, 88, 93, 76, 84];
const routePanel = document.getElementById("route-panel");
const metricGrid = document.getElementById("metric-grid");
const workoutList = document.getElementById("workout-list");
const aiPanel = document.getElementById("ai-panel");
const pageTitle = document.getElementById("page-title");
const pageSubtitle = document.getElementById("page-subtitle");
const waterFill = document.getElementById("water-fill");
const waterGoalPill = document.getElementById("water-goal-pill");
const waterCopy = document.getElementById("water-copy");

function loadPrefs() {
  const saved = JSON.parse(localStorage.getItem("fittrack_prefs") || "{}");
  return {
    waterGoal: saved.waterGoal || 3.2,
    athleteName: saved.athleteName || "Jordan Lee"
  };
}

function savePrefs(prefs) {
  localStorage.setItem("fittrack_prefs", JSON.stringify(prefs));
}

function renderMetrics() {
  metricGrid.innerHTML = dashboardMetrics.map((item) => `
    <article class="metric-card ${item.tone}">
      <p class="label">${item.label}</p>
      <h3>${item.value}</h3>
      <span class="mini-copy">Updated in the latest sync</span>
    </article>
  `).join("");
}

function renderWorkouts() {
  workoutList.innerHTML = workouts.map((item) => `
    <div class="workout-card">
      <div>
        <strong>${item.name}</strong>
        <p>${item.meta}</p>
      </div>
      <span class="pill">${item.status}</span>
    </div>
  `).join("");
}

function renderAiPanel() {
  aiPanel.innerHTML = `
    <div class="ai-copy">
      <strong>Coach recommendation</strong>
      <p>Shift tomorrow to a lower-impact conditioning block, then increase protein intake by 18g after the evening workout.</p>
    </div>
    <div class="ai-copy">
      <strong>Macro alert</strong>
      <p>Carbs are under target by 12%. Hydration consistency remains the easiest win this week.</p>
    </div>
  `;
}

function renderChart() {
  const canvas = document.getElementById("progress-chart");
  const ctx = canvas.getContext("2d");
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#10253a";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  const gap = 18;
  const barWidth = 56;
  chartBars.forEach((value, index) => {
    const x = 36 + index * (barWidth + gap);
    const y = canvas.height - value * 2.2 - 28;
    ctx.fillStyle = "#ff8b5e";
    ctx.fillRect(x, y, barWidth, value * 2.2);
    ctx.fillStyle = "#eef6ff";
    ctx.font = "14px sans-serif";
    ctx.fillText(["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][index], x + 10, canvas.height - 8);
  });
}

function renderRoutePanel() {
  const path = window.location.pathname;
  const prefs = loadPrefs();
  let panelTitle = "Dashboard route";
  let panelCopy = "Weekly metrics, recovery signals, and retention-friendly UX are all visible on this route.";

  if (path === "/") {
    pageTitle.textContent = "FitTrack AI Landing Page";
    pageSubtitle.textContent = "Modern fitness SaaS landing page with progress preview, product promise, and quick links into the app.";
    panelTitle = "Landing page";
    panelCopy = "This route is designed to look strong in sandbox screenshots with visible cards, chart, and fake AI guidance.";
  } else if (path === "/dashboard") {
    pageTitle.textContent = "FitTrack AI Performance Dashboard";
    panelTitle = "Dashboard";
    panelCopy = "Visible metrics include steps, macros, hydration, sleep score, and workout planning actions.";
  } else if (path === "/login") {
    pageTitle.textContent = "FitTrack AI Login";
    panelTitle = "Login route";
    panelCopy = "This is a simple demo login route for sandbox reachability checks.";
  } else if (path === "/admin") {
    pageTitle.textContent = "FitTrack AI Admin Panel";
    panelTitle = "Admin route";
    panelCopy = "This unprotected admin route intentionally shows privileged-looking content without authentication.";
  } else if (path === "/debug") {
    pageTitle.textContent = "FitTrack AI Debug Console";
    panelTitle = "Debug route";
    panelCopy = "This route intentionally exposes fake environment and diagnostic information for runtime testing.";
  }

  routePanel.innerHTML = `
    <div class="panel-head">
      <div>
        <p class="label">Route spotlight</p>
        <h3>${panelTitle}</h3>
      </div>
      <span class="pill">${path}</span>
    </div>
    <p>${panelCopy}</p>
    ${path === "/admin" ? `
      <div class="admin-grid">
        <div class="admin-card"><strong>Billing overrides</strong><p>Visible to any visitor in this demo route.</p></div>
        <div class="admin-card"><strong>Coach approvals</strong><p>12 pending member plan approvals.</p></div>
      </div>
    ` : ""}
    ${path === "/debug" ? `
      <pre class="debug-box">ENV=demo
API_KEY=fittrack_fake_frontend_key
SUPPORT_EMAIL=coach@example.com
FEATURE_FLAGS=beta-ai-plan, hydration-reminders</pre>
    ` : ""}
    ${path === "/login" ? `
      <div class="login-card">
        <label>Email<input type="email" value="coach@example.com" /></label>
        <label>Password<input type="password" value="admin123" /></label>
        <button class="primary-btn" type="button">Sign In</button>
      </div>
    ` : ""}
    <p class="muted">Saved preference athlete: ${prefs.athleteName}</p>
  `;
}

function renderWaterTracker() {
  const prefs = loadPrefs();
  const current = 2.4;
  waterGoalPill.textContent = `Goal ${prefs.waterGoal.toFixed(1)}L`;
  waterFill.style.width = `${Math.min(100, (current / prefs.waterGoal) * 100)}%`;
  waterCopy.textContent = `${current.toFixed(1)}L logged today. ${current >= prefs.waterGoal ? "Goal reached." : "Add one more glass to close the gap."}`;
}

function wireModal() {
  const modal = document.getElementById("workout-modal");
  const addWorkoutBtn = document.getElementById("add-workout-btn");
  const closeModalBtn = document.getElementById("close-modal-btn");
  const workoutForm = document.getElementById("workout-form");
  const feedback = document.getElementById("modal-feedback");

  addWorkoutBtn.addEventListener("click", () => modal.classList.remove("hidden"));
  closeModalBtn.addEventListener("click", () => modal.classList.add("hidden"));
  workoutForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const workoutName = document.getElementById("workout-name").value || "Custom Workout";
    const duration = document.getElementById("workout-duration").value || "30";
    feedback.textContent = `Saved ${workoutName} for ${duration} minutes in local demo state.`;
    const prefs = loadPrefs();
    prefs.athleteName = "Coach Preview User";
    savePrefs(prefs);
  });
}

function wireGeneratePlan() {
  document.getElementById("generate-plan-btn").addEventListener("click", () => {
    const prefs = loadPrefs();
    prefs.waterGoal = 3.6;
    savePrefs(prefs);
    renderWaterTracker();
    renderRoutePanel();
  });
}

renderMetrics();
renderWorkouts();
renderAiPanel();
renderChart();
renderRoutePanel();
renderWaterTracker();
wireModal();
wireGeneratePlan();
