// server.js
const express = require("express");
const app = express();

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

const PORT = 4000;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
