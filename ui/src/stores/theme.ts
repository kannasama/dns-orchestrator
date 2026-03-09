import { defineStore } from 'pinia'
import { ref, computed, watch } from 'vue'
import { updatePreset } from '@primevue/themes'
import { getDarkPreset, getLightPreset, registerCustomPresets } from '../theme/presets'
import type { ThemePreset } from '../theme/presets'
import { listCustomThemes } from '../api/themes'

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

  async function loadCustomPresets() {
    try {
      const customs = await listCustomThemes()
      if (customs.length > 0) {
        const mapped: ThemePreset[] = customs.map(c => ({
          name: c.name,
          label: c.label,
          mode: c.mode,
          defaultAccent: c.defaultAccent,
          surface: {
            0: c.surface['0'] ?? '#ffffff',
            50: c.surface['50'] ?? '',
            100: c.surface['100'] ?? '',
            200: c.surface['200'] ?? '',
            300: c.surface['300'] ?? '',
            400: c.surface['400'] ?? '',
            500: c.surface['500'] ?? '',
            600: c.surface['600'] ?? '',
            700: c.surface['700'] ?? '',
            800: c.surface['800'] ?? '',
            900: c.surface['900'] ?? '',
            950: c.surface['950'] ?? '',
          },
        }))
        registerCustomPresets(mapped)
        // Re-apply current preset in case a custom preset is active
        applyPreset()
      }
    } catch {
      // Custom themes are optional — fail silently
    }
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
  loadCustomPresets()

  return {
    darkMode, darkTheme, lightTheme, accent, accentOverride,
    fontFamily, fontSize, gridFontSize, activePreset,
    toggleDarkMode, setAccent, setDarkTheme, setLightTheme,
    setFontFamily, setFontSize, setGridFontSize, loadCustomPresets,
  }
})
