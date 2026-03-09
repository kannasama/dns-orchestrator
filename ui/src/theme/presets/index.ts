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

export function registerCustomPresets(presets: ThemePreset[]) {
  for (const preset of presets) {
    if (preset.mode === 'dark') {
      if (!darkPresets.some(p => p.name === preset.name)) {
        darkPresets.push(preset)
      }
    } else {
      if (!lightPresets.some(p => p.name === preset.name)) {
        lightPresets.push(preset)
      }
    }
  }
}

export type { ThemePreset, SurfacePalette } from './types'
