import { computed } from 'vue'
import { useAuthStore } from '../stores/auth'

export function useRole() {
  const auth = useAuthStore()

  return {
    isAdmin: computed(() => auth.role === 'admin'),
    isOperator: computed(() => auth.role === 'operator' || auth.role === 'admin'),
    isViewer: computed(() => true),
  }
}
