/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        panel: "#0f172a",
        panel2: "#111827",
        accent: "#38bdf8",
        critical: "#ef4444",
        high: "#f97316",
        medium: "#eab308",
        low: "#22c55e",
      },
    },
  },
  plugins: [],
}
