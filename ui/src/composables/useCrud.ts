import { type Ref, ref } from 'vue'
import { useNotificationStore } from '../stores/notification'
import { ApiRequestError } from '../api/client'

interface CrudApi<T, C, U> {
  list: (...args: unknown[]) => Promise<T[]>
  create: (data: C) => Promise<{ id: number }>
  update: (id: number, data: U) => Promise<{ message: string }>
  remove: (id: number) => Promise<{ message: string }>
}

export function useCrud<T extends { id: number }, C = Partial<T>, U = Partial<T>>(
  api: CrudApi<T, C, U>,
  entityName: string,
) {
  const items: Ref<T[]> = ref([]) as Ref<T[]>
  const loading = ref(false)

  const notify = useNotificationStore()

  async function fetchItems(...args: unknown[]) {
    loading.value = true
    try {
      items.value = await api.list(...args)
    } catch (err) {
      const msg = err instanceof ApiRequestError ? err.body.message : 'Failed to load'
      notify.error(`Failed to load ${entityName}s`, msg)
    } finally {
      loading.value = false
    }
  }

  async function createItem(data: C): Promise<boolean> {
    try {
      await api.create(data)
      notify.success(`${entityName} created`)
      await fetchItems()
      return true
    } catch (err) {
      const msg = err instanceof ApiRequestError ? err.body.message : 'Failed to create'
      notify.error(`Failed to create ${entityName}`, msg)
      return false
    }
  }

  async function updateItem(id: number, data: U): Promise<boolean> {
    try {
      await api.update(id, data)
      notify.success(`${entityName} updated`)
      await fetchItems()
      return true
    } catch (err) {
      const msg = err instanceof ApiRequestError ? err.body.message : 'Failed to update'
      notify.error(`Failed to update ${entityName}`, msg)
      return false
    }
  }

  async function removeItem(id: number): Promise<boolean> {
    try {
      await api.remove(id)
      notify.success(`${entityName} deleted`)
      await fetchItems()
      return true
    } catch (err) {
      const msg = err instanceof ApiRequestError ? err.body.message : 'Failed to delete'
      notify.error(`Failed to delete ${entityName}`, msg)
      return false
    }
  }

  return { items, loading, fetch: fetchItems, create: createItem, update: updateItem, remove: removeItem }
}
