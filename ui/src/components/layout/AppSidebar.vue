<script setup lang="ts">
import { useRoute } from 'vue-router'

const route = useRoute()

const navItems = [
  { label: 'Dashboard', icon: 'pi pi-home', to: '/' },
  { label: 'Providers', icon: 'pi pi-server', to: '/providers' },
  { label: 'Views', icon: 'pi pi-eye', to: '/views' },
  { label: 'Zones', icon: 'pi pi-globe', to: '/zones' },
  { label: 'Variables', icon: 'pi pi-code', to: '/variables' },
  { label: 'Deployments', icon: 'pi pi-upload', to: '/deployments' },
  { label: 'Audit Log', icon: 'pi pi-history', to: '/audit' },
]

function isActive(to: string) {
  if (to === '/') return route.path === '/'
  return route.path.startsWith(to)
}
</script>

<template>
  <nav class="app-sidebar" aria-label="Main navigation">
    <ul class="app-sidebar-nav">
      <li v-for="item in navItems" :key="item.to">
        <router-link
          :to="item.to"
          class="app-nav-item"
          :class="{ active: isActive(item.to) }"
        >
          <i :class="item.icon" />
          <span>{{ item.label }}</span>
        </router-link>
      </li>
    </ul>
  </nav>
</template>

<style scoped>
.app-sidebar {
  width: 14rem;
  min-height: 100%;
  background: var(--p-surface-900);
  border-right: 1px solid var(--p-surface-700);
  padding-top: 0.5rem;
}

:root:not(.app-dark) .app-sidebar {
  background: var(--p-surface-50);
  border-right-color: var(--p-surface-200);
}

.app-sidebar-nav {
  list-style: none;
  margin: 0;
  padding: 0;
}

.app-nav-item {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.65rem 1.25rem;
  color: var(--p-surface-300);
  text-decoration: none;
  font-size: 0.875rem;
  border-left: 3px solid transparent;
  transition: background 0.15s, color 0.15s;
}

:root:not(.app-dark) .app-nav-item {
  color: var(--p-surface-600);
}

.app-nav-item:hover {
  background: var(--p-surface-800);
  color: var(--p-surface-0);
}

:root:not(.app-dark) .app-nav-item:hover {
  background: var(--p-surface-100);
  color: var(--p-surface-900);
}

.app-nav-item.active {
  border-left-color: var(--p-primary-400);
  background: color-mix(in srgb, var(--p-primary-400) 10%, transparent);
  color: var(--p-primary-400);
  font-weight: 600;
}

:root:not(.app-dark) .app-nav-item.active {
  border-left-color: var(--p-primary-600);
  background: color-mix(in srgb, var(--p-primary-600) 8%, transparent);
  color: var(--p-primary-600);
}

.app-nav-item i {
  font-size: 1rem;
  width: 1.25rem;
  text-align: center;
}
</style>
