import { render } from "preact";
import { App } from "./app";
import "./theme.css";
import "./ui.css";
import "./app.css";

const root = document.getElementById("app");
if (root) {
  render(<App />, root);
}
