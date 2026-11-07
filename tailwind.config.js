// Builds static/vendor/tailwind.css, so the dashboard loads no third-party
// scripts (see README, "Rebuilding the stylesheet").
module.exports = {
  content: ["./static/*.html", "./static/*.js"],
  theme: { extend: {} },
  plugins: [],
};
