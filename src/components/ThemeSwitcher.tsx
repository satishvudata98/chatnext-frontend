import type { FC } from "react";
import { useTheme } from "../context/ThemeContext";

const ThemeSwitcher: FC = () => {
  const { theme, toggleTheme } = useTheme();
  return (
    <button
      aria-label={theme === "light" ? "Switch to dark mode" : "Switch to light mode"}
      onClick={toggleTheme}
      style={{
        background: "none",
        border: "none",
        cursor: "pointer",
        fontSize: "1.2rem",
        marginLeft: 8,
        color: "var(--color-text)"
      }}
      title={theme === "light" ? "Switch to dark mode" : "Switch to light mode"}
    >
      {theme === "light" ? "🌙" : "☀️"}
    </button>
  );
};

export default ThemeSwitcher;