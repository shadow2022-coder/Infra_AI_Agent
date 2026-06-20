const express = require("express");
const path = require("path");
require("dotenv").config();

const app = express();
const port = Number(process.env.PORT || 3000);

const workouts = [
  { id: 1, name: "Upper Body Strength", duration: 42, calories: 390, status: "Completed" },
  { id: 2, name: "Recovery Run", duration: 28, calories: 240, status: "Scheduled" },
  { id: 3, name: "Mobility Flow", duration: 18, calories: 110, status: "Completed" }
];

const profile = {
  name: "Jordan Lee",
  tier: "Pro Coach Preview",
  weeklyGoal: "5 workouts",
  supportEmail: "coach@example.com"
};

app.use(express.json());
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Set-Cookie", [
    "session=fake_session_cookie_fittrack; Path=/",
    "refresh_token=fake_refresh_cookie_fittrack; Path=/; HttpOnly"
  ]);
  next();
});

app.use(express.static(path.join(__dirname, "public")));

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, app: "FitTrack AI", sandboxReady: true });
});

app.get("/api/workouts", (_req, res) => {
  res.json({ workouts, generatedAt: new Date().toISOString() });
});

app.get("/api/profile", (_req, res) => {
  res.json(profile);
});

app.get(["/", "/dashboard", "/login", "/admin", "/debug"], (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

console.log("FitTrack AI fake token:", process.env.SESSION_TOKEN);
console.log("FitTrack AI frontend config:", process.env.NEXT_PUBLIC_SUPABASE_KEY);

app.listen(port, "0.0.0.0", () => {
  console.log(`FitTrack AI running on port ${port}`);
});
