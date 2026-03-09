# Workstream 1: UI Visual Overhaul — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Restyle all existing views with Dockhand-inspired structural patterns and implement the full 23-preset named theme system. No new pages or features — purely visual.

**Architecture:** Theme presets are standalone TypeScript files in `ui/src/theme/presets/`, each exporting surface/border/text color tokens plus a default accent. The theme store manages independent light/dark preset selection with an accent override flag. PrimeVue's `updatePreset()` API applies tokens at runtime. Font customization uses CSS custom properties persisted to localStorage.

**Tech Stack:** Vue 3, TypeScript, PrimeVue 4.5.4 (Aura preset base), Pinia, CSS custom properties

---

## Task Overview

| # | Task | Description |
|---|------|-------------|
| 1 | Theme preset type + Default presets | Define `ThemePreset` type, create Default dark + light presets |
| 2 | Remaining dark presets (13) | All 13 non-default dark theme presets |
| 3 | Remaining light presets (8) | All 8 non-default light theme presets |
| 4 | Preset index + registry | Central registry exporting all presets by name |
| 5 | Theme store refactor | Add `lightTheme`/`darkTheme` + preset application logic |
| 6 | Appearance section in ProfileView | Theme preset dropdowns + font customization controls |
| 7 | AppTopBar — move accent picker to profile | Simplify top bar, remove accent popover |
| 8 | Surface layering + visual density | Update layout and all views with proper surface hierarchy |
| 9 | Zone switcher | Zone dropdown in top bar on ZoneDetailView |
| 10 | Full visual verification pass | Manual QA across all 14 views × multiple presets |

---

### Task 1: Theme Preset Type + Default Presets

**Files:**
- Create: `ui/src/theme/presets/types.ts`
- Create: `ui/src/theme/presets/dark/default.ts`
- Create: `ui/src/theme/presets/light/default.ts`

The `ThemePreset` type defines the contract all 23 presets will follow. The Default presets extract the current hardcoded zinc/slate surfaces from `ui/src/theme/preset.ts`.

**Step 1: Create the ThemePreset type**

Create `ui/src/theme/presets/types.ts`:

```typescript
export interface SurfacePalette {
  0: string
  50: string
  100: string
  200: string
  300: string
  400: string
  500: string
  600: string
  700: string
  800: string
  900: string
  950: string
}

export interface ThemePreset {
  name: string
  label: string
  mode: 'dark' | 'light'
  defaultAccent: string        // Tailwind palette name (e.g., 'indigo', 'purple')
  surface: SurfacePalette
}
```

**Step 2: Create Default dark preset**

Create `ui/src/theme/presets/dark/default.ts`:

```typescript
import type { ThemePreset } from '../types'

const preset: ThemePreset = {
  name: 'default',
  label: 'Default',
  mode: 'dark',
  defaultAccent: 'indigo',
  surface: {
    0: '#ffffff',
    50: '{zinc.50}',
    100: '{zinc.100}',
    200: '{zinc.200}',
    300: '{zinc.300}',
    400: '{zinc.400}',
    500: '{zinc.500}',
    600: '{zinc.600}',
    700: '{zinc.700}',
    800: '{zinc.800}',
    900: '{zinc.900}',
    950: '{zinc.950}',
  },
}

export default preset
```

**Step 3: Create Default light preset**

Create `ui/src/theme/presets/light/default.ts`:

```typescript
import type { ThemePreset } from '../types'

const preset: ThemePreset = {
  name: 'default',
  label: 'Default',
  mode: 'light',
  defaultAccent: 'indigo',
  surface: {
    0: '#ffffff',
    50: '{slate.50}',
    100: '{slate.100}',
    200: '{slate.200}',
    300: '{slate.300}',
    400: '{slate.400}',
    500: '{slate.500}',
    600: '{slate.600}',
    700: '{slate.700}',
    800: '{slate.800}',
    900: '{slate.900}',
    950: '{slate.950}',
  },
}

export default preset
```

**Step 4: Verify build compiles**

Run: `cd ui && npx vue-tsc --noEmit`
Expected: No type errors.

**Step 5: Commit**

```bash
git add ui/src/theme/presets/
git commit -m "feat(ui): add ThemePreset type and Default dark/light presets"
```

---

### Task 2: Remaining Dark Presets (13)

**Files:**
- Create: `ui/src/theme/presets/dark/catppuccin-mocha.ts`
- Create: `ui/src/theme/presets/dark/dracula.ts`
- Create: `ui/src/theme/presets/dark/rose-pine.ts`
- Create: `ui/src/theme/presets/dark/rose-pine-moon.ts`
- Create: `ui/src/theme/presets/dark/nord.ts`
- Create: `ui/src/theme/presets/dark/tokyo-night.ts`
- Create: `ui/src/theme/presets/dark/gruvbox-dark.ts`
- Create: `ui/src/theme/presets/dark/solarized-dark.ts`
- Create: `ui/src/theme/presets/dark/kanagawa.ts`
- Create: `ui/src/theme/presets/dark/monokai-pro.ts`
- Create: `ui/src/theme/presets/dark/material-dark.ts`
- Create: `ui/src/theme/presets/dark/ayu-dark.ts`
- Create: `ui/src/theme/presets/dark/github-dark.ts`

Each preset file follows the same structure as Default dark. Surface colors use hardcoded hex values derived from the official theme palette, **not** PrimeVue Aura token references (since these are custom palettes outside Aura's named colors).

**Implementation guidance:** For each theme, use the official color palette from the theme's documentation to generate a surface ramp of 13 values (0, 50, 100 ... 950). Surface 0 is always `#ffffff`. Surface 950 is the deepest background. Surface 900 is the primary page background. Surface 800 is the card/elevated surface. Surface 700 is the border color. Surface 50-400 are text colors at various emphasis levels.

Here is the color mapping for each preset. The implementer should look up exact hex values from each theme's official documentation/repository.

| Preset | Surface Base | `defaultAccent` | Reference |
|--------|-------------|-----------------|-----------|
| Catppuccin Mocha | `#1e1e2e` (base) → `#313244` (surface1) → `#45475a` (surface2) | `purple` | catppuccin.com |
| Dracula | `#282a36` (bg) → `#44475a` (current line) → `#6272a4` (comment) | `purple` | draculatheme.com |
| Rose Pine | `#191724` (base) → `#1f1d2e` (surface) → `#26233a` (overlay) | `rose` | rosepinetheme.com |
| Rose Pine Moon | `#232136` (base) → `#2a273f` (surface) → `#393552` (overlay) | `rose` | rosepinetheme.com |
| Nord | `#2e3440` (nord0) → `#3b4252` (nord1) → `#434c5e` (nord2) → `#4c566a` (nord3) | `sky` | nordtheme.com |
| Tokyo Night | `#1a1b26` (bg) → `#24283b` (bg_dark) → `#414868` (comment) | `violet` | github.com/enkia |
| Gruvbox Dark | `#282828` (bg) → `#3c3836` (bg1) → `#504945` (bg2) | `orange` | github.com/morhetz/gruvbox |
| Solarized Dark | `#002b36` (base03) → `#073642` (base02) → `#586e75` (base01) | `blue` | ethanschoonover.com/solarized |
| Kanagawa | `#1f1f28` (sumiInk3) → `#2a2a37` (sumiInk4) → `#363646` (sumiInk5) | `blue` | github.com/rebelot/kanagawa |
| Monokai Pro | `#2d2a2e` (bg) → `#403e41` (line) → `#727072` (comment) | `amber` | monokai.pro |
| Material Dark | `#212121` (bg) → `#303030` (surface) → `#424242` (overlay) | `cyan` | material-theme.com |
| Ayu Dark | `#0a0e14` (bg) → `#0d1017` (panel) → `#131721` (line) | `amber` | github.com/ayu-theme |
| GitHub Dark | `#0d1117` (canvas) → `#161b22` (surface) → `#21262d` (overlay) | `blue` | github.com/primer |

**Example — Catppuccin Mocha:**

```typescript
import type { ThemePreset } from '../types'

const preset: ThemePreset = {
  name: 'catppuccin-mocha',
  label: 'Catppuccin Mocha',
  mode: 'dark',
  defaultAccent: 'purple',
  surface: {
    0: '#ffffff',
    50: '#f5e0dc',    // rosewater — lightest text
    100: '#cdd6f4',   // text
    200: '#bac2de',   // subtext1
    300: '#a6adc8',   // subtext0
    400: '#9399b2',   // overlay2
    500: '#7f849c',   // overlay1
    600: '#6c7086',   // overlay0
    700: '#585b70',   // surface2 — borders
    800: '#45475a',   // surface1 — elevated
    900: '#313244',   // surface0 — cards
    950: '#1e1e2e',   // base — page background
  },
}

export default preset
```

**Step 1: Create all 13 dark preset files**

Follow the example pattern above for each theme. Look up the official color palettes and distribute them across the 50–950 surface ramp, keeping this mental model:
- 950 = deepest background (page)
- 900 = card surface
- 800 = elevated/hover surface
- 700 = borders
- 600 = muted text / dividers
- 500–300 = mid-range text
- 200–100 = primary text
- 50 = lightest accent/highlight

**Step 2: Verify TypeScript compiles**

Run: `cd ui && npx vue-tsc --noEmit`
Expected: No type errors.

**Step 3: Commit**

```bash
git add ui/src/theme/presets/dark/
git commit -m "feat(ui): add 13 dark theme presets"
```

---

### Task 3: Remaining Light Presets (8)

**Files:**
- Create: `ui/src/theme/presets/light/catppuccin-latte.ts`
- Create: `ui/src/theme/presets/light/rose-pine-dawn.ts`
- Create: `ui/src/theme/presets/light/nord-light.ts`
- Create: `ui/src/theme/presets/light/solarized-light.ts`
- Create: `ui/src/theme/presets/light/alucard.ts`
- Create: `ui/src/theme/presets/light/material-light.ts`
- Create: `ui/src/theme/presets/light/ayu-light.ts`
- Create: `ui/src/theme/presets/light/github-light.ts`

Same structure as dark presets, but the surface ramp is inverted — 950 is the darkest text and 50 is the lightest background. Surface 0 matches or is close to the page background.

| Preset | Surface Base | `defaultAccent` | Reference |
|--------|-------------|-----------------|-----------|
| Catppuccin Latte | `#eff1f5` (base) → `#e6e9ef` (mantle) → `#dce0e8` (crust) | `purple` | catppuccin.com |
| Rose Pine Dawn | `#faf4ed` (base) → `#fffaf3` (surface) → `#f2e9e1` (overlay) | `rose` | rosepinetheme.com |
| Nord Light | `#eceff4` (nord6) → `#e5e9f0` (nord5) → `#d8dee9` (nord4) | `sky` | nordtheme.com |
| Solarized Light | `#fdf6e3` (base3) → `#eee8d5` (base2) → `#93a1a1` (base1) | `blue` | ethanschoonover.com/solarized |
| Alucard (Dracula) | `#f8f8f2` (fg as bg) → `#f0f0f0` → `#e0e0e0` | `purple` | draculatheme.com |
| Material Light | `#fafafa` (bg) → `#f5f5f5` (surface) → `#eeeeee` (overlay) | `cyan` | material-theme.com |
| Ayu Light | `#fafafa` (bg) → `#f3f4f5` (panel) → `#e7e8e9` (line) | `orange` | github.com/ayu-theme |
| GitHub Light | `#ffffff` (canvas) → `#f6f8fa` (surface) → `#d0d7de` (border) | `blue` | github.com/primer |

**Step 1: Create all 8 light preset files**

Light mode surface ramp mental model:
- 0 = white (or close to it)
- 50 = page background (lightest tint)
- 100 = card/elevated surface
- 200 = borders
- 300 = dividers / disabled
- 400–500 = muted/secondary text
- 600–700 = body text
- 800–900 = headings / emphasis text
- 950 = darkest text

**Step 2: Verify TypeScript compiles**

Run: `cd ui && npx vue-tsc --noEmit`
Expected: No type errors.

**Step 3: Commit**

```bash
git add ui/src/theme/presets/light/
git commit -m "feat(ui): add 8 light theme presets"
```

---

### Task 4: Preset Index + Registry

**Files:**
- Create: `ui/src/theme/presets/index.ts`

Central registry that imports all 23 presets and exports lookup functions.

**Step 1: Create the preset registry**

Create `ui/src/theme/presets/index.ts`:

```typescript
import type { ThemePreset } from './types'

// Dark presets
import darkDefault from './dark/default'
import catppuccinMocha from './dark/catppuccin-mocha'
import dracula from './dark/dracula'
import rosePine from './dark/rose-pine'
import rosePineMoon from './dark/rose-pine-moon'
import nord from './dark/nord'
import tokyoNight from './dark/tokyo-night'
import gruvboxDark from './dark/gruvbox-dark'
import solarizedDark from './dark/solarized-dark'
import kanagawa from './dark/kanagawa'
import monokaiPro from './dark/monokai-pro'
import materialDark from './dark/material-dark'
import ayuDark from './dark/ayu-dark'
import githubDark from './dark/github-dark'

// Light presets
import lightDefault from './light/default'
import catppuccinLatte from './light/catppuccin-latte'
import rosePineDawn from './light/rose-pine-dawn'
import nordLight from './light/nord-light'
import solarizedLight from './light/solarized-light'
import alucard from './light/alucard'
import materialLight from './light/material-light'
import ayuLight from './light/ayu-light'
import githubLight from './light/github-light'

export const darkPresets: ThemePreset[] = [
  darkDefault,
  catppuccinMocha,
  dracula,
  rosePine,
  rosePineMoon,
  nord,
  tokyoNight,
  gruvboxDark,
  solarizedDark,
  kanagawa,
  monokaiPro,
  materialDark,
  ayuDark,
  githubDark,
]

export const lightPresets: ThemePreset[] = [
  lightDefault,
  catppuccinLatte,
  rosePineDawn,
  nordLight,
  solarizedLight,
  alucard,
  materialLight,
  ayuLight,
  githubLight,
]

export function getDarkPreset(name: string): ThemePreset {
  return darkPresets.find(p => p.name === name) ?? darkDefault
}

export function getLightPreset(name: string): ThemePreset {
  return lightPresets.find(p => p.name === name) ?? lightDefault
}

export type { ThemePreset, SurfacePalette } from './types'
```

**Step 2: Verify TypeScript compiles**

Run: `cd ui && npx vue-tsc --noEmit`
Expected: No type errors.

**Step 3: Commit**

```bash
git add ui/src/theme/presets/index.ts
git commit -m "feat(ui): add preset registry with lookup functions"
```

---

### Task 5: Theme Store Refactor

**Files:**
- Modify: `ui/src/stores/theme.ts`
- Modify: `ui/src/theme/preset.ts`

This is the core change. The store gains `lightTheme` and `darkTheme` preset name properties. Switching presets calls `updatePreset()` to change surface colors. An `accentOverride` flag tracks whether the user manually chose an accent.

**Step 1: Update the theme store**

Replace `ui/src/stores/theme.ts` with:

```typescript
import { defineStore } from 'pinia'
import { ref, computed, watch } from 'vue'
import { updatePreset } from '@primevue/themes'
import { getDarkPreset, getLightPreset } from '../theme/presets'
import type { ThemePreset } from '../theme/presets'

export type AccentColor =
  | 'noir' | 'emerald' | 'green' | 'lime'
  | 'orange' | 'amber' | 'yellow' | 'cyan'
  | 'sky' | 'blue' | 'indigo' | 'violet'
  | 'purple' | 'fuchsia' | 'pink' | 'rose'

export const useThemeStore = defineStore('theme', () => {
  const darkMode = ref(localStorage.getItem('theme-dark') !== 'false')
  const darkTheme = ref(localStorage.getItem('theme-dark-preset') || 'default')
  const lightTheme = ref(localStorage.getItem('theme-light-preset') || 'default')
  const accent = ref<AccentColor>(
    (localStorage.getItem('theme-accent') as AccentColor) || 'indigo',
  )
  const accentOverride = ref(localStorage.getItem('theme-accent-override') === 'true')

  // Font customization
  const fontFamily = ref(localStorage.getItem('theme-font-family') || 'system')
  const fontSize = ref(localStorage.getItem('theme-font-size') || '14')
  const gridFontSize = ref(localStorage.getItem('theme-grid-font-size') || '13')

  const activePreset = computed<ThemePreset>(() =>
    darkMode.value ? getDarkPreset(darkTheme.value) : getLightPreset(lightTheme.value),
  )

  function applyDarkMode() {
    if (darkMode.value) {
      document.documentElement.classList.add('app-dark')
    } else {
      document.documentElement.classList.remove('app-dark')
    }
  }

  function applyAccent(color: AccentColor) {
    const palette = color === 'noir' ? 'zinc' : color
    updatePreset({
      semantic: {
        primary: {
          50: `{${palette}.50}`,
          100: `{${palette}.100}`,
          200: `{${palette}.200}`,
          300: `{${palette}.300}`,
          400: `{${palette}.400}`,
          500: `{${palette}.500}`,
          600: `{${palette}.600}`,
          700: `{${palette}.700}`,
          800: `{${palette}.800}`,
          900: `{${palette}.900}`,
          950: `{${palette}.950}`,
        },
      },
    })
  }

  function applySurface(preset: ThemePreset) {
    const mode = preset.mode === 'dark' ? 'dark' : 'light'
    updatePreset({
      semantic: {
        colorScheme: {
          [mode]: {
            surface: { ...preset.surface },
          },
        },
      },
    })
  }

  function applyFonts() {
    const root = document.documentElement
    const family = fontFamily.value === 'system'
      ? "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
      : fontFamily.value === 'inter'
        ? "'Inter', sans-serif"
        : `'${fontFamily.value}', sans-serif`
    root.style.setProperty('--app-font-family', family)
    root.style.setProperty('--app-font-size', `${fontSize.value}px`)
    root.style.setProperty('--app-grid-font-size', `${gridFontSize.value}px`)
  }

  function applyPreset() {
    const preset = activePreset.value
    applySurface(preset)
    if (!accentOverride.value) {
      accent.value = preset.defaultAccent as AccentColor
    }
    applyAccent(accent.value)
  }

  function toggleDarkMode() {
    darkMode.value = !darkMode.value
  }

  function setAccent(color: AccentColor) {
    accentOverride.value = true
    accent.value = color
  }

  function setDarkTheme(name: string) {
    darkTheme.value = name
    accentOverride.value = false
  }

  function setLightTheme(name: string) {
    lightTheme.value = name
    accentOverride.value = false
  }

  function setFontFamily(family: string) {
    fontFamily.value = family
  }

  function setFontSize(size: string) {
    fontSize.value = size
  }

  function setGridFontSize(size: string) {
    gridFontSize.value = size
  }

  // Persist to localStorage
  watch(darkMode, (val) => {
    localStorage.setItem('theme-dark', String(val))
    applyDarkMode()
    applyPreset()
  })

  watch(darkTheme, (val) => {
    localStorage.setItem('theme-dark-preset', val)
    if (darkMode.value) applyPreset()
  })

  watch(lightTheme, (val) => {
    localStorage.setItem('theme-light-preset', val)
    if (!darkMode.value) applyPreset()
  })

  watch(accent, (val) => {
    localStorage.setItem('theme-accent', val)
    localStorage.setItem('theme-accent-override', String(accentOverride.value))
    applyAccent(val)
  })

  watch(fontFamily, (val) => {
    localStorage.setItem('theme-font-family', val)
    applyFonts()
  })

  watch(fontSize, (val) => {
    localStorage.setItem('theme-font-size', val)
    applyFonts()
  })

  watch(gridFontSize, (val) => {
    localStorage.setItem('theme-grid-font-size', val)
    applyFonts()
  })

  // Apply on init
  applyDarkMode()
  applyPreset()
  applyFonts()

  return {
    darkMode, darkTheme, lightTheme, accent, accentOverride,
    fontFamily, fontSize, gridFontSize, activePreset,
    toggleDarkMode, setAccent, setDarkTheme, setLightTheme,
    setFontFamily, setFontSize, setGridFontSize,
  }
})
```

**Step 2: Verify the existing preset.ts still works**

The base `ui/src/theme/preset.ts` remains unchanged — it provides the Aura foundation. The store's `updatePreset()` calls override the surface colors at runtime. No changes needed to `preset.ts` or `index.ts`.

**Step 3: Verify build compiles**

Run: `cd ui && npx vue-tsc --noEmit`
Expected: No type errors.

**Step 4: Verify dev server loads**

Run: `cd ui && npm run dev`
Expected: App loads in browser with default theme (zinc dark / slate light). Toggling dark mode switches surfaces. No console errors.

**Step 5: Commit**

```bash
git add ui/src/stores/theme.ts
git commit -m "feat(ui): refactor theme store for named presets + font customization"
```

---

### Task 6: Appearance Section in ProfileView

**Files:**
- Modify: `ui/src/views/ProfileView.vue`

Add an "Appearance" card section to ProfileView with:
- Dark theme preset dropdown (14 options)
- Light theme preset dropdown (9 options)
- Accent color picker (existing 16-color grid — moved from AppTopBar)
- Font family dropdown (system, Inter, Roboto, etc.)
- Font size dropdown (12, 13, 14, 15, 16)
- Grid font size dropdown (11, 12, 13, 14, 15)

**Step 1: Add imports and appearance state to ProfileView script**

At the top of `<script setup>`, add:

```typescript
import Select from 'primevue/select'
import { useThemeStore, type AccentColor } from '../stores/theme'
import { darkPresets, lightPresets } from '../theme/presets'

const theme = useThemeStore()

const fontFamilyOptions = [
  { label: 'System Default', value: 'system' },
  { label: 'Inter', value: 'inter' },
  { label: 'Roboto', value: 'Roboto' },
  { label: 'Source Sans 3', value: 'Source Sans 3' },
]

const fontSizeOptions = ['12', '13', '14', '15', '16'].map(s => ({ label: `${s}px`, value: s }))
const gridFontSizeOptions = ['11', '12', '13', '14', '15'].map(s => ({ label: `${s}px`, value: s }))

const darkPresetOptions = darkPresets.map(p => ({ label: p.label, value: p.name }))
const lightPresetOptions = lightPresets.map(p => ({ label: p.label, value: p.name }))

const colorRows: { name: AccentColor; bg: string }[][] = [
  [
    { name: 'noir', bg: '#71717a' },
    { name: 'emerald', bg: '#10b981' },
    { name: 'green', bg: '#22c55e' },
    { name: 'lime', bg: '#84cc16' },
    { name: 'orange', bg: '#f97316' },
    { name: 'amber', bg: '#f59e0b' },
    { name: 'yellow', bg: '#eab308' },
    { name: 'cyan', bg: '#06b6d4' },
  ],
  [
    { name: 'sky', bg: '#0ea5e9' },
    { name: 'blue', bg: '#3b82f6' },
    { name: 'indigo', bg: '#6366f1' },
    { name: 'violet', bg: '#8b5cf6' },
    { name: 'purple', bg: '#a855f7' },
    { name: 'fuchsia', bg: '#d946ef' },
    { name: 'pink', bg: '#ec4899' },
    { name: 'rose', bg: '#f43f5e' },
  ],
]
```

**Step 2: Add the Appearance section template**

Insert a new `<section>` block after the "Change Password" section and before the "API Keys" section:

```html
<section class="profile-section">
  <h3 class="section-title"><i class="pi pi-palette section-icon" /> Appearance</h3>

  <div class="appearance-grid">
    <div class="field">
      <label>Dark Theme</label>
      <Select
        :modelValue="theme.darkTheme"
        @update:modelValue="theme.setDarkTheme($event)"
        :options="darkPresetOptions"
        optionLabel="label"
        optionValue="value"
        class="w-full"
      />
    </div>
    <div class="field">
      <label>Light Theme</label>
      <Select
        :modelValue="theme.lightTheme"
        @update:modelValue="theme.setLightTheme($event)"
        :options="lightPresetOptions"
        optionLabel="label"
        optionValue="value"
        class="w-full"
      />
    </div>
  </div>

  <div class="field mt-1">
    <label>Accent Color</label>
    <div class="color-grid">
      <div v-for="(row, ri) in colorRows" :key="ri" class="color-row">
        <button
          v-for="c in row"
          :key="c.name"
          class="color-swatch"
          :class="{ active: theme.accent === c.name }"
          :style="{ backgroundColor: c.bg }"
          :title="c.name"
          @click="theme.setAccent(c.name)"
        >
          <i v-if="theme.accent === c.name" class="pi pi-check swatch-check" />
        </button>
      </div>
    </div>
  </div>

  <div class="appearance-grid mt-1">
    <div class="field">
      <label>Font Family</label>
      <Select
        :modelValue="theme.fontFamily"
        @update:modelValue="theme.setFontFamily($event)"
        :options="fontFamilyOptions"
        optionLabel="label"
        optionValue="value"
        class="w-full"
      />
    </div>
    <div class="field">
      <label>Font Size</label>
      <Select
        :modelValue="theme.fontSize"
        @update:modelValue="theme.setFontSize($event)"
        :options="fontSizeOptions"
        optionLabel="label"
        optionValue="value"
        class="w-full"
      />
    </div>
    <div class="field">
      <label>Table Font Size</label>
      <Select
        :modelValue="theme.gridFontSize"
        @update:modelValue="theme.setGridFontSize($event)"
        :options="gridFontSizeOptions"
        optionLabel="label"
        optionValue="value"
        class="w-full"
      />
    </div>
  </div>
</section>
```

**Step 3: Add appearance-specific styles**

Add to the `<style scoped>` section:

```css
.section-icon {
  margin-right: 0.5rem;
  font-size: 1rem;
}

.appearance-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(12rem, 1fr));
  gap: 1rem;
}

.mt-1 {
  margin-top: 1rem;
}

.color-grid {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.color-row {
  display: flex;
  gap: 0.5rem;
}

.color-swatch {
  width: 1.5rem;
  height: 1.5rem;
  border-radius: 50%;
  border: 2px solid transparent;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0;
  transition: transform 0.15s;
}

.color-swatch:hover {
  transform: scale(1.2);
}

.color-swatch.active {
  border-color: var(--p-surface-0);
  box-shadow: 0 0 0 1px var(--p-surface-500);
}

.swatch-check {
  font-size: 0.625rem;
  color: white;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);
}
```

**Step 4: Also add icon headers to the existing sections**

Update the existing section titles to use icons for consistency:

- "Profile" → `<i class="pi pi-user section-icon" /> Profile`
- "Change Password" → `<i class="pi pi-lock section-icon" /> Change Password`
- "API Keys" → `<i class="pi pi-key section-icon" /> API Keys`

**Step 5: Verify in dev server**

Run: `cd ui && npm run dev`
Expected: Profile page shows 4 card sections. Theme dropdowns change the surface colors. Accent grid changes the primary color. Font dropdowns update custom properties.

**Step 6: Commit**

```bash
git add ui/src/views/ProfileView.vue
git commit -m "feat(ui): add appearance settings section to profile page"
```

---

### Task 7: AppTopBar — Simplify

**Files:**
- Modify: `ui/src/components/layout/AppTopBar.vue`

The accent color picker moves to ProfileView (Task 6). Remove the palette popover from the top bar. Keep the dark/light toggle button.

**Step 1: Remove the accent popover**

In `AppTopBar.vue`:

1. Remove the `accentPopover` ref, `colorRows` data, and `toggleAccentPopover` function
2. Remove the Popover import and the `<Popover>` template block
3. Remove the palette `<Button>` (`icon="pi pi-palette"`)
4. Remove all `.color-*` and `.swatch-*` CSS rules
5. Keep the dark mode toggle button and user menu

**Step 2: Verify in dev server**

Run: `cd ui && npm run dev`
Expected: Top bar shows only dark toggle + user menu. No palette button. Accent is now only changeable via Profile > Appearance.

**Step 3: Commit**

```bash
git add ui/src/components/layout/AppTopBar.vue
git commit -m "refactor(ui): move accent picker from top bar to profile appearance"
```

---

### Task 8: Surface Layering + Visual Density

**Files:**
- Modify: `ui/src/components/layout/AppShell.vue`
- Modify: `ui/src/components/layout/AppTopBar.vue`
- Modify: `ui/src/components/layout/AppSidebar.vue`
- Modify: `ui/src/style.css`
- Modify: All 14 view files (as needed)

This task applies the Dockhand-inspired surface layering: distinct background (950), card surface (900), and elevated surface (800) in dark mode. Tighten padding and spacing across all views.

**Step 1: Update global CSS with font custom properties**

In `ui/src/style.css`, add after the existing rules:

```css
html, body {
  font-family: var(--app-font-family, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif);
  font-size: var(--app-font-size, 14px);
}
```

And add DataTable grid font size override:

```css
.p-datatable .p-datatable-tbody > tr > td,
.p-datatable .p-datatable-thead > tr > th {
  font-size: var(--app-grid-font-size, 13px);
}
```

**Step 2: Update AppShell surface layering**

In `AppShell.vue`, the content area uses `surface-950` (dark) — this is the page background. This is already correct. No change needed.

**Step 3: Tighten visual density**

In views that use `.stat-card`, `.profile-section`, or similar card patterns, reduce padding from `1.25rem` to `1rem` where space is tight. Reduce `gap` in `.stats-grid` from `1rem` to `0.75rem` if it feels too spread out.

Review each view and make surgical adjustments:

- **DashboardView:** Reduce `.stat-card` padding to `0.75rem 1rem`. Reduce `.stats-grid` gap to `0.75rem`.
- **ProfileView:** Padding is fine at `1.25rem` — form sections need breathing room.
- **All DataTable views:** Already using `size="small"` — verify spacing looks good with new surface colors. No changes needed unless tables look too spread out.
- **DeploymentsView:** Reduce `.diff-row` padding slightly if needed.

**Step 4: Add section-title icon pattern globally**

In `DashboardView.vue`, update the section titles to use icons:

```html
<h3 class="section-title"><i class="pi pi-server section-icon" /> Provider Health</h3>
...
<h3 class="section-title"><i class="pi pi-globe section-icon" /> Zones</h3>
```

Add `.section-icon { margin-right: 0.5rem; }` to the scoped styles.

**Step 5: Verify across multiple presets**

Run: `cd ui && npm run dev`

Switch between at least 3 presets (Default, Catppuccin Mocha, Nord) in both dark and light modes. Verify:
- Surface layering is visible (background vs cards vs elevated)
- Borders are visible but not harsh
- Text is readable at all emphasis levels
- DataTables look clean with the new surface colors
- No visual regressions on login/setup/change-password pages

**Step 6: Commit**

```bash
git add ui/src/style.css ui/src/components/layout/ ui/src/views/
git commit -m "feat(ui): apply surface layering and visual density improvements"
```

---

### Task 9: Zone Switcher

**Files:**
- Modify: `ui/src/views/ZoneDetailView.vue`

Add a zone dropdown to the page header area in ZoneDetailView for quick zone switching. This replaces navigating back to the zone list.

**Step 1: Add zone list fetching and dropdown**

In `ZoneDetailView.vue` script section, add:

```typescript
const allZones = ref<Zone[]>([])

// Inside fetchData(), after the existing zone/record fetch:
zoneApi.listZones().then(z => { allZones.value = z }).catch(() => {})
```

**Step 2: Add the zone selector to the template**

In the `<PageHeader>` section, add a zone dropdown before the action buttons:

```html
<PageHeader :title="zone.name" subtitle="Zone records">
  <Select
    :modelValue="zoneId"
    @update:modelValue="(id: number) => router.push({ name: 'zone-detail', params: { id } })"
    :options="allZones"
    optionLabel="name"
    optionValue="id"
    placeholder="Switch zone..."
    class="zone-switcher mr-2"
    filter
    filterPlaceholder="Search zones..."
  />
  <!-- existing buttons -->
</PageHeader>
```

**Step 3: Add zone-switcher styling**

```css
.zone-switcher {
  width: 14rem;
}
```

**Step 4: Handle route param change**

The current `zoneId` is computed once from `route.params.id`. To support switching without full remount, make `zoneId` reactive:

```typescript
const zoneId = computed(() => Number(route.params.id))
```

And add a watcher to refetch data when it changes:

```typescript
watch(zoneId, () => {
  fetchData()
})
```

Update all references from the `const zoneId` number to the `zoneId.value` computed.

**Step 5: Verify zone switching works**

Run: `cd ui && npm run dev`
Expected: ZoneDetailView shows a filterable dropdown in the header. Selecting a different zone navigates to it and reloads records. Back/forward browser navigation also works.

**Step 6: Commit**

```bash
git add ui/src/views/ZoneDetailView.vue
git commit -m "feat(ui): add zone switcher dropdown to zone detail page"
```

---

### Task 10: Full Visual Verification Pass

**Files:** None (QA task)

This is not a code task — it's a verification pass across the entire UI.

**Step 1: Test all 14 views**

Run: `cd ui && npm run dev`

Navigate through every view in the app:
1. Login page
2. Dashboard
3. Providers
4. Views
5. Zones
6. Zone Detail (with records)
7. Variables
8. Deployments
9. Audit Log
10. Users (admin)
11. Groups (admin)
12. Profile (all 4 sections)
13. Setup page (if accessible)
14. Change Password page

For each view, verify:
- Surfaces render correctly (no white/black flashing, no missing backgrounds)
- Text is readable against the background
- Borders are visible but not harsh
- Buttons, tags, badges use the accent color correctly
- DataTables are legible with the font size settings
- Drawer/dialog forms have proper surface layering

**Step 2: Test at least 4 presets**

Cycle through:
1. Default dark + Default light
2. Catppuccin Mocha + Catppuccin Latte
3. Nord dark + Nord Light
4. Dracula + Alucard

Verify each pair looks cohesive end-to-end.

**Step 3: Test accent color override persistence**

1. Select Catppuccin Mocha (should apply purple accent)
2. Manually pick blue accent → accent override = true
3. Switch to Nord → accent should stay blue (override persisted)
4. Select Nord again (via dropdown, which resets override) → accent should change to sky
5. Refresh page → preset + accent should persist from localStorage

**Step 4: Test font customization**

1. Change font family to Inter → body text should change
2. Change font size to 16px → UI should scale
3. Change grid font size to 11px → DataTable cells should shrink
4. Refresh page → settings persist

**Step 5: Test zone switcher**

1. Navigate to any zone detail
2. Use the dropdown to switch to another zone
3. Verify records reload correctly
4. Use browser back button → returns to previous zone

**Step 6: Fix any issues found, then commit**

If any fixes are needed, commit them:

```bash
git add -u
git commit -m "fix(ui): visual polish from verification pass"
```

**Step 7: Verify production build**

Run: `cd ui && npm run build`
Expected: Build completes without errors. Check `ui/dist/` output size is reasonable.

---

## Notes for Implementer

### PrimeVue updatePreset() Behavior

`updatePreset()` from `@primevue/themes` merges the provided object into the active theme at runtime. It accepts partial objects — you can update just `semantic.colorScheme.dark.surface` without affecting other tokens. This is how presets work: the base Aura preset provides all component tokens, and `updatePreset()` overrides just the surface + primary palettes.

**Important:** `updatePreset()` must be called after the PrimeVue plugin is installed. The theme store's init code runs when the store is first accessed (during component mount), which is after `app.use(PrimeVue)` in `main.ts`. This ordering is correct and should not be changed.

### Surface Color Token Usage in Views

All existing views use `var(--p-surface-XXX)` CSS custom properties. These are automatically updated when `updatePreset()` changes the surface palette. **No CSS changes are needed in individual views** for presets to take effect — the token system handles it.

The only CSS changes needed are for visual density (padding/spacing adjustments) and the font custom properties.

### Presets with Hardcoded Hex vs Token References

The Default dark/light presets use Aura token references (e.g., `{zinc.500}`) because those colors are defined in the Aura base. All other presets use hardcoded hex values because their palettes aren't part of Aura's named colors. This is correct — `updatePreset()` accepts both forms.

### Font Loading

The font family dropdown offers system font, Inter, Roboto, and Source Sans 3. These are web fonts that the user must have installed locally or you must add them via Google Fonts. For v1.0, stick with locally-available fonts (system font stack). If you want web font loading, add `<link>` tags to `ui/index.html` for the fonts or use `@import` in `style.css`. This is a nice-to-have, not a blocker.

### What NOT to Change

- Do not change the page routing structure
- Do not change the sidebar navigation items or layout
- Do not change any API calls or data fetching logic
- Do not change the user menu in the top bar
- Do not add new views or routes
- Do not change the PrimeVue component library or version
