/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        noc: {
          bg: "#0B0F19",
          card: "#111827",
          border: "#1F2937",
          muted: "#9CA3AF",
          accent: "#3B82F6",
          success: "#10B981",
          warning: "#F59E0B",
          danger: "#EF4444",
          sidebar: "#0D1322",
        },
      },
    },
  },
  plugins: [],
};
