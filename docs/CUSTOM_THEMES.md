# Custom Theme Specification

Meridian DNS ships with 23 built-in theme presets (14 dark, 9 light). Administrators can add
custom presets by placing JSON files in a configured directory. Custom themes appear alongside
built-in presets in the Appearance settings and behave identically.

---

## Directory

Custom theme files are stored in:

```
/var/lib/meridian-dns/custom_themes/
```

This is a fixed path — no configuration variable is needed. Place `.json` theme files in this
directory. The directory is scanned on each `GET /api/v1/themes` request, so new themes are
picked up without a restart.

- If the directory does not exist, the API returns an empty array silently.
- Non-`.json` files and subdirectories are ignored.

In Docker Compose, mount a host directory to this path:

```yaml
services:
  app:
    volumes:
      - ./themes:/var/lib/meridian-dns/custom_themes:ro
```

---

## Theme File Format

Each `.json` file in the themes directory defines one preset. Non-`.json` files are ignored.

### Schema

```json
{
  "name": "my-dark-theme",
  "label": "My Dark Theme",
  "mode": "dark",
  "defaultAccent": "purple",
  "surface": {
    "0": "#ffffff",
    "50": "#f5e0dc",
    "100": "#cdd6f4",
    "200": "#bac2de",
    "300": "#a6adc8",
    "400": "#9399b2",
    "500": "#7f849c",
    "600": "#6c7086",
    "700": "#585b70",
    "800": "#45475a",
    "900": "#313244",
    "950": "#1e1e2e"
  }
}
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique identifier. Lowercase with hyphens (e.g., `my-dark-theme`). Must not conflict with a built-in preset name — conflicts are silently ignored. |
| `label` | string | Yes | Display name shown in the theme dropdown (e.g., `My Dark Theme`). |
| `mode` | string | Yes | Either `"dark"` or `"light"`. Determines which dropdown the preset appears in. |
| `defaultAccent` | string | Yes | Tailwind CSS palette name used as the default accent color when this preset is selected. See [Accent Colors](#accent-colors). |
| `surface` | object | Yes | 13-entry surface color palette. Keys are `"0"` through `"950"`. Values are hex color strings. See [Surface Palette](#surface-palette). |

Files missing any required field are skipped. Files that fail JSON parsing are skipped. No
errors are returned — invalid files are silently ignored.

---

## Surface Palette

The surface palette defines the layered color ramp that controls backgrounds, borders, and text
throughout the UI. PrimeVue maps these to `--p-surface-{n}` CSS custom properties.

### Dark Mode Mapping

In dark mode, high numbers are backgrounds and low numbers are text:

| Key | Role | Example Usage |
|-----|------|---------------|
| `0` | Pure white | Always `#ffffff` — used for contrast text on primary-colored backgrounds |
| `50` | Lightest accent | Highlights, hover text emphasis |
| `100` | Primary text | Headings, body text |
| `200` | Secondary text | Subheadings, emphasized labels |
| `300` | Tertiary text | Descriptions, secondary content |
| `400` | Muted text | Placeholders, disabled content |
| `500` | Mid-range | Icons, subtle dividers |
| `600` | Subdued | Muted icons, secondary borders |
| `700` | Borders | Card borders, table dividers |
| `800` | Elevated surface | Cards, popovers, dropdowns |
| `900` | Card surface | Main content cards, panels |
| `950` | Page background | Deepest background layer |

### Light Mode Mapping

In light mode, the ramp inverts — low numbers are backgrounds, high numbers are text:

| Key | Role | Example Usage |
|-----|------|---------------|
| `0` | White | Page background or near-white base |
| `50` | Page background | Lightest background tint |
| `100` | Card surface | Elevated content areas |
| `200` | Borders | Card borders, table dividers |
| `300` | Dividers | Subtle separators, disabled borders |
| `400` | Muted text | Placeholders, disabled content |
| `500` | Secondary text | Descriptions, labels |
| `600` | Body text | Standard paragraph text |
| `700` | Emphasis text | Subheadings, links |
| `800` | Strong text | Headings, navigation items |
| `900` | Primary text | Page titles, strong emphasis |
| `950` | Darkest text | Maximum contrast text |

### Design Guidelines

- **Contrast:** Ensure at least 4.5:1 contrast ratio between text colors (50–300 for dark, 600–950
  for light) and their background surfaces (800–950 for dark, 50–100 for light).
- **Gradual ramp:** Adjacent steps should transition smoothly. Avoid large jumps between
  consecutive levels — the ramp should feel like a cohesive gradient.
- **Surface 0:** Always set to `#ffffff`. This is used for text on primary-colored buttons and
  badges where white text is expected regardless of theme.
- **Source your palette:** Use the official color values from the theme you're adapting. Most
  popular editor themes publish their full palette (base, surface, overlay, text, and highlight
  colors) which map naturally to this 13-step ramp.

---

## Accent Colors

The `defaultAccent` field sets the primary/accent color applied when a user selects this preset
(unless they have manually overridden their accent). The value must be one of these Tailwind CSS
palette names:

| Name | Hex Sample | Name | Hex Sample |
|------|-----------|------|-----------|
| `noir` | `#71717a` | `sky` | `#0ea5e9` |
| `emerald` | `#10b981` | `blue` | `#3b82f6` |
| `green` | `#22c55e` | `indigo` | `#6366f1` |
| `lime` | `#84cc16` | `violet` | `#8b5cf6` |
| `orange` | `#f97316` | `purple` | `#a855f7` |
| `amber` | `#f59e0b` | `fuchsia` | `#d946ef` |
| `yellow` | `#eab308` | `pink` | `#ec4899` |
| `cyan` | `#06b6d4` | `rose` | `#f43f5e` |

Choose an accent that complements your surface palette. For example, warm surfaces (Gruvbox,
Monokai) pair well with `orange` or `amber`, while cool surfaces (Nord, Solarized) pair well
with `blue` or `sky`.

---

## API

### `GET /api/v1/themes`

Returns all custom theme presets. No authentication required.

**Response:** `200 OK`

```json
[
  {
    "name": "my-dark-theme",
    "label": "My Dark Theme",
    "mode": "dark",
    "defaultAccent": "purple",
    "surface": {
      "0": "#ffffff",
      "50": "#f5e0dc",
      "100": "#cdd6f4",
      "200": "#bac2de",
      "300": "#a6adc8",
      "400": "#9399b2",
      "500": "#7f849c",
      "600": "#6c7086",
      "700": "#585b70",
      "800": "#45475a",
      "900": "#313244",
      "950": "#1e1e2e"
    }
  }
]
```

Returns an empty array if the feature is disabled or no valid theme files exist.

---

## Examples

### Minimal Dark Theme

```json
{
  "name": "midnight",
  "label": "Midnight",
  "mode": "dark",
  "defaultAccent": "blue",
  "surface": {
    "0": "#ffffff",
    "50": "#e2e8f0",
    "100": "#cbd5e1",
    "200": "#94a3b8",
    "300": "#64748b",
    "400": "#475569",
    "500": "#334155",
    "600": "#2d3748",
    "700": "#252d3a",
    "800": "#1e2530",
    "900": "#171d27",
    "950": "#0f1318"
  }
}
```

### Minimal Light Theme

```json
{
  "name": "paper",
  "label": "Paper",
  "mode": "light",
  "defaultAccent": "emerald",
  "surface": {
    "0": "#ffffff",
    "50": "#fafaf9",
    "100": "#f5f5f4",
    "200": "#e7e5e4",
    "300": "#d6d3d1",
    "400": "#a8a29e",
    "500": "#78716c",
    "600": "#57534e",
    "700": "#44403c",
    "800": "#292524",
    "900": "#1c1917",
    "950": "#0c0a09"
  }
}
```

### Adapting an Editor Theme

To create a preset from an existing editor theme (e.g., One Dark Pro):

1. Find the theme's official color palette — look for background, foreground, and UI surface
   colors in the theme repository or documentation.
2. Identify the key colors:
   - **Background** → `950` (dark) or `50` (light)
   - **Elevated/panel surface** → `900`/`800`
   - **Border/gutter** → `700`
   - **Comment/muted** → `500`/`600`
   - **Foreground text** → `100`/`200`
3. Interpolate missing steps to create a smooth ramp between your anchor colors.
4. Pick an accent that matches the theme's signature highlight color.
5. Save as a `.json` file in the themes directory.

---

## Name Conflicts

If a custom theme has the same `name` as a built-in preset, the built-in preset takes
precedence and the custom theme is ignored. Built-in preset names:

**Dark:** `default`, `catppuccin-mocha`, `dracula`, `rose-pine`, `rose-pine-moon`, `nord`,
`tokyo-night`, `gruvbox-dark`, `solarized-dark`, `kanagawa`, `monokai-pro`, `material-dark`,
`ayu-dark`, `github-dark`

**Light:** `default`, `catppuccin-latte`, `rose-pine-dawn`, `nord-light`, `solarized-light`,
`alucard`, `material-light`, `ayu-light`, `github-light`

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Theme doesn't appear in dropdown | Invalid JSON or missing required field | Validate the file with `jq . theme.json` and check all 5 fields are present |
| Theme appears but surfaces look wrong | Incorrect key names in `surface` object | Keys must be strings: `"0"`, `"50"`, `"100"`, ..., `"950"` (13 entries) |
| Accent color doesn't apply | Invalid `defaultAccent` value | Must be one of the 16 Tailwind palette names listed above |
| No themes returned from API | Directory doesn't exist or contains no `.json` files | Verify `/var/lib/meridian-dns/custom_themes/` exists and contains valid `.json` files |
| Theme conflicts with built-in | Same `name` as a built-in preset | Rename the custom theme's `name` field |
