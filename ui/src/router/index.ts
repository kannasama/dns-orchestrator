import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import { getSetupStatus } from '../api/setup'

let setupChecked = false
let setupRequired = false

export function markSetupComplete() {
  setupRequired = false
}

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: () => import('../views/LoginView.vue'),
      meta: { public: true },
    },
    {
      path: '/auth/callback',
      name: 'auth-callback',
      component: () => import('../views/AuthCallbackView.vue'),
      meta: { public: true },
    },
    {
      path: '/setup',
      name: 'setup',
      component: () => import('../views/SetupView.vue'),
      meta: { public: true },
    },
    {
      path: '/change-password',
      name: 'change-password',
      component: () => import('../views/ChangePasswordView.vue'),
    },
    {
      path: '/',
      component: () => import('../components/layout/AppShell.vue'),
      children: [
        {
          path: '',
          name: 'dashboard',
          component: () => import('../views/DashboardView.vue'),
        },
        {
          path: 'providers',
          name: 'providers',
          component: () => import('../views/ProvidersView.vue'),
        },
        {
          path: 'views',
          name: 'views',
          component: () => import('../views/ViewsView.vue'),
        },
        {
          path: 'zones',
          name: 'zones',
          component: () => import('../views/ZonesView.vue'),
        },
        {
          path: 'zones/:id',
          name: 'zone-detail',
          component: () => import('../views/ZoneDetailView.vue'),
        },
        {
          path: 'variables',
          name: 'variables',
          component: () => import('../views/VariablesView.vue'),
        },
        {
          path: 'git-repos',
          name: 'git-repos',
          component: () => import('../views/GitReposView.vue'),
        },
        {
          path: 'deployments',
          name: 'deployments',
          component: () => import('../views/DeploymentsView.vue'),
        },
        {
          path: 'audit',
          name: 'audit',
          component: () => import('../views/AuditView.vue'),
        },
        {
          path: 'profile',
          name: 'profile',
          component: () => import('../views/ProfileView.vue'),
        },

        // ─── Administration routes ───
        {
          path: 'admin/auth',
          name: 'admin-auth',
          component: () => import('../views/AdminAuthView.vue'),
        },
        {
          path: 'admin/identity-providers',
          name: 'admin-identity-providers',
          component: () => import('../views/IdentityProvidersView.vue'),
        },
        {
          path: 'admin/settings',
          name: 'admin-settings',
          component: () => import('../views/SettingsView.vue'),
        },

        // ─── Backward-compatible redirects ───
        {
          path: 'users',
          redirect: { name: 'admin-auth', query: { tab: 'users' } },
        },
        {
          path: 'groups',
          redirect: { name: 'admin-auth', query: { tab: 'groups' } },
        },
        {
          path: 'roles',
          redirect: { name: 'admin-auth', query: { tab: 'permissions' } },
        },
        {
          path: 'identity-providers',
          redirect: { name: 'admin-identity-providers' },
        },
        {
          path: 'settings',
          redirect: { name: 'admin-settings' },
        },
      ],
    },
  ],
})

router.beforeEach(async (to) => {
  // Check setup status once on app load
  if (!setupChecked) {
    try {
      const status = await getSetupStatus()
      setupRequired = status.setup_required
    } catch {
      // If the endpoint fails, assume setup is not required
      setupRequired = false
    }
    setupChecked = true
  }

  // Redirect to /setup if setup is required
  if (setupRequired && to.name !== 'setup') {
    return { name: 'setup' }
  }

  // Redirect away from /setup if setup is already complete
  if (!setupRequired && to.name === 'setup') {
    return { name: 'login' }
  }

  if (to.meta.public) return true

  const auth = useAuthStore()
  if (!auth.isAuthenticated) {
    const valid = await auth.hydrate()
    if (!valid) {
      return { name: 'login' }
    }
  }

  if (auth.user?.force_password_change && to.name !== 'change-password' && to.name !== 'login') {
    return { name: 'change-password' }
  }

  return true
})

export default router
