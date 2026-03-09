import { get } from './client'

export interface CustomThemePreset {
  name: string
  label: string
  mode: 'dark' | 'light'
  defaultAccent: string
  surface: Record<string, string>
}

export function listCustomThemes(): Promise<CustomThemePreset[]> {
  return get('/themes')
}
