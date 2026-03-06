import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '../stores/auth'

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
          path: 'deployments',
          name: 'deployments',
          component: () => import('../views/DeploymentsView.vue'),
        },
        {
          path: 'audit',
          name: 'audit',
          component: () => import('../views/AuditView.vue'),
        },
      ],
    },
  ],
})

router.beforeEach(async (to) => {
  if (to.meta.public) return true

  const auth = useAuthStore()
  if (!auth.isAuthenticated) {
    const valid = await auth.hydrate()
    if (!valid) {
      return { name: 'login' }
    }
  }
  return true
})

export default router
