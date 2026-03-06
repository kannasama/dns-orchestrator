<script setup lang="ts">
import { ref } from 'vue'
import Button from 'primevue/button'
import Menu from 'primevue/menu'
import Tag from 'primevue/tag'
import { useAuthStore } from '../../stores/auth'
import { useThemeStore, type AccentColor } from '../../stores/theme'
import { useRouter } from 'vue-router'

const auth = useAuthStore()
const theme = useThemeStore()
const router = useRouter()

const userMenu = ref()
const accentMenu = ref()

const userMenuItems = ref([
  {
    label: auth.user?.username ?? '',
    items: [
      {
        label: 'Logout',
        icon: 'pi pi-sign-out',
        command: async () => {
          await auth.logout()
          router.push('/login')
        },
      },
    ],
  },
])

const accentColors: { label: string; value: AccentColor }[] = [
  { label: 'Indigo', value: 'indigo' },
  { label: 'Blue', value: 'blue' },
  { label: 'Teal', value: 'teal' },
  { label: 'Green', value: 'green' },
  { label: 'Amber', value: 'amber' },
  { label: 'Rose', value: 'rose' },
]

const accentMenuItems = ref(
  accentColors.map((c) => ({
    label: c.label,
    command: () => theme.setAccent(c.value),
  })),
)

function toggleUserMenu(event: Event) {
  userMenu.value.toggle(event)
}

function toggleAccentMenu(event: Event) {
  accentMenu.value.toggle(event)
}
</script>

<template>
  <header class="app-topbar">
    <div class="app-topbar-start">
      <span class="app-wordmark">Meridian DNS</span>
    </div>
    <div class="app-topbar-end">
      <Button
        :icon="theme.darkMode ? 'pi pi-sun' : 'pi pi-moon'"
        text
        rounded
        aria-label="Toggle theme"
        @click="theme.toggleDarkMode()"
      />
      <Button
        icon="pi pi-palette"
        text
        rounded
        aria-label="Accent color"
        @click="toggleAccentMenu"
      />
      <Menu ref="accentMenu" :model="accentMenuItems" :popup="true" />
      <Button
        text
        rounded
        aria-label="User menu"
        @click="toggleUserMenu"
      >
        <span class="app-user-label">{{ auth.user?.username }}</span>
        <Tag :value="auth.role" severity="secondary" class="ml-2" />
      </Button>
      <Menu ref="userMenu" :model="userMenuItems" :popup="true" />
    </div>
  </header>
</template>

<style scoped>
.app-topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 3.5rem;
  padding: 0 1.5rem;
  background: var(--p-surface-900);
  border-bottom: 1px solid var(--p-surface-700);
}

:root:not(.app-dark) .app-topbar {
  background: var(--p-surface-50);
  border-bottom-color: var(--p-surface-200);
}

.app-topbar-start {
  display: flex;
  align-items: center;
}

.app-wordmark {
  font-size: 1.15rem;
  font-weight: 700;
  color: var(--p-primary-400);
  letter-spacing: -0.01em;
}

:root:not(.app-dark) .app-wordmark {
  color: var(--p-primary-600);
}

.app-topbar-end {
  display: flex;
  align-items: center;
  gap: 0.25rem;
}

.app-user-label {
  font-size: 0.875rem;
}

.ml-2 {
  margin-left: 0.5rem;
}
</style>
