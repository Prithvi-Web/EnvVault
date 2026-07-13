import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";

// Platform class drives the background strategy: vibrancy tint on macOS and
// Windows, solid color on Linux (no compositor blur guaranteed there).
const ua = navigator.userAgent;
document.body.classList.add(
  ua.includes("Mac") ? "plat-mac" : ua.includes("Linux") ? "plat-linux" : "plat-win",
);

const root = document.getElementById("root");
if (!root) {
  throw new Error("missing #root element");
}

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
