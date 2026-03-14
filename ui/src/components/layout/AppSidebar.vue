<script setup lang="ts">
import { ref } from 'vue'
import { useRoute } from 'vue-router'
import { useAuthStore } from '../../stores/auth'

const route = useRoute()
const auth = useAuthStore()

const mainNavItems = [
  { label: 'Dashboard', icon: 'pi pi-home', to: '/' },
  { label: 'Providers', icon: 'pi pi-server', to: '/providers' },
  { label: 'Views', icon: 'pi pi-eye', to: '/views' },
  { label: 'Zones', icon: 'pi pi-globe', to: '/zones' },
  { label: 'Variables', icon: 'pi pi-code', to: '/variables' },
  { label: 'Git Repos', icon: 'pi pi-github', to: '/git-repos' },
  { label: 'Deployments', icon: 'pi pi-upload', to: '/deployments' },
  { label: 'Audit Log', icon: 'pi pi-history', to: '/audit' },
]

const adminNavItems = [
  { label: 'Auth', icon: 'pi pi-users', to: '/admin/auth' },
  { label: 'Identity Providers', icon: 'pi pi-key', to: '/admin/identity-providers' },
  { label: 'Settings', icon: 'pi pi-cog', to: '/admin/settings' },
]

const adminExpanded = ref(true)

function isActive(to: string) {
  if (to === '/') return route.path === '/'
  return route.path.startsWith(to)
}

function isAdminActive() {
  return route.path.startsWith('/admin')
}
</script>

<template>
  <nav class="app-sidebar" aria-label="Main navigation">
    <ul class="app-sidebar-nav">
      <li v-for="item in mainNavItems" :key="item.to">
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

    <div v-if="auth.isAdmin" class="admin-section">
      <button
        class="admin-section-header"
        :class="{ active: isAdminActive() }"
        @click="adminExpanded = !adminExpanded"
      >
        <i class="pi pi-wrench" />
        <span>Administration</span>
        <i
          class="pi expand-icon"
          :class="adminExpanded ? 'pi-chevron-down' : 'pi-chevron-right'"
        />
      </button>
      <ul v-show="adminExpanded" class="app-sidebar-nav admin-nav">
        <li v-for="item in adminNavItems" :key="item.to">
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
    </div>
  </nav>
</template>

<style scoped>
.app-sidebar {
  width: 14rem;
  min-height: 100%;
  background: var(--p-surface-900);
  border-right: 1px solid var(--p-surface-700);
  padding-top: 0.5rem;
  display: flex;
  flex-direction: column;
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

/* Administration section */
.admin-section {
  margin-top: 0.5rem;
  border-top: 1px solid var(--p-surface-700);
  padding-top: 0.25rem;
}

:root:not(.app-dark) .admin-section {
  border-top-color: var(--p-surface-200);
}

.admin-section-header {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  width: 100%;
  padding: 0.65rem 1.25rem;
  background: none;
  border: none;
  border-left: 3px solid transparent;
  color: var(--p-surface-400);
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  cursor: pointer;
  transition: color 0.15s;
}

.admin-section-header:hover {
  color: var(--p-surface-200);
}

:root:not(.app-dark) .admin-section-header {
  color: var(--p-surface-500);
}

:root:not(.app-dark) .admin-section-header:hover {
  color: var(--p-surface-700);
}

.admin-section-header.active {
  color: var(--p-primary-400);
}

:root:not(.app-dark) .admin-section-header.active {
  color: var(--p-primary-600);
}

.admin-section-header i:first-child {
  font-size: 0.875rem;
  width: 1.25rem;
  text-align: center;
}

.expand-icon {
  margin-left: auto;
  font-size: 0.625rem !important;
  width: auto !important;
}

.admin-nav .app-nav-item {
  padding-left: 1.75rem;
  font-size: 0.8125rem;
}
</style>
