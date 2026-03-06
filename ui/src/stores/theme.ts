import { defineStore } from 'pinia'
import { ref, watch } from 'vue'

export type AccentColor = 'indigo' | 'blue' | 'teal' | 'green' | 'amber' | 'rose'

export const useThemeStore = defineStore('theme', () => {
  const darkMode = ref(localStorage.getItem('theme-dark') !== 'false')
  const accent = ref<AccentColor>(
    (localStorage.getItem('theme-accent') as AccentColor) || 'indigo',
  )

  function applyDarkMode() {
    if (darkMode.value) {
      document.documentElement.classList.add('app-dark')
    } else {
      document.documentElement.classList.remove('app-dark')
    }
  }

  function toggleDarkMode() {
    darkMode.value = !darkMode.value
  }

  function setAccent(color: AccentColor) {
    accent.value = color
  }

  watch(darkMode, (val) => {
    localStorage.setItem('theme-dark', String(val))
    applyDarkMode()
  })

  watch(accent, (val) => {
    localStorage.setItem('theme-accent', val)
  })

  // Apply on init
  applyDarkMode()

  return { darkMode, accent, toggleDarkMode, setAccent }
})
