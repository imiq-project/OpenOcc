/** @type {import('tailwindcss').Config} */

const {heroui} = require("@heroui/react");

module.exports = {
    content: [
        "./src/**/*.{js,ts,jsx,tsx,mdx}",
        "./node_modules/@heroui/theme/dist/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                occ: {
                    bg: "rgb(var(--occ-bg) / <alpha-value>)",
                    surface: "rgb(var(--occ-surface) / <alpha-value>)",
                    "surface-raised": "rgb(var(--occ-surface-raised) / <alpha-value>)",
                    border: "rgb(var(--occ-border) / <alpha-value>)",
                    deep: "rgb(var(--occ-deep) / <alpha-value>)",
                    nav: "rgb(var(--occ-nav) / <alpha-value>)",
                    "nav-border": "rgb(var(--occ-nav-border) / <alpha-value>)",
                },
            },
            spacing: {
                "panel-sm": "14rem",   /* 224px — vehicle list */
                "panel-md": "18rem",   /* 288px — detail panels */
                "panel-lg": "21.25rem",/* 340px — info side panel */
            },
        },
    },
    darkMode: "class",
    plugins: [heroui({
        defaultTheme: "light",
        themes: {
            light: {
                colors: {
                    primary: {
                        50: "#fdf2f7",
                        100: "#fce7f1",
                        200: "#fbcfe4",
                        300: "#f9a8cd",
                        400: "#f472aa",
                        500: "#e8457f",
                        600: "#c4265a",
                        700: "#a31842",
                        800: "#7b0038",
                        900: "#5c0029",
                        DEFAULT: "#7b0038",
                        foreground: "#ffffff",
                    },
                },
            },
        },
    })],
}
