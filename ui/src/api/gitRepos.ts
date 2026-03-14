import { get, post, put, del } from './client'
import type { GitRepo, GitRepoCreate, GitRepoUpdate } from '../types'

export function listGitRepos(): Promise<GitRepo[]> {
  return get('/git-repos')
}

export function getGitRepo(id: number): Promise<GitRepo> {
  return get(`/git-repos/${id}`)
}

export function createGitRepo(data: GitRepoCreate): Promise<{ id: number; name: string }> {
  return post('/git-repos', data)
}

export function updateGitRepo(id: number, data: GitRepoUpdate): Promise<{ message: string }> {
  return put(`/git-repos/${id}`, data)
}

export function deleteGitRepo(id: number): Promise<{ message: string }> {
  return del(`/git-repos/${id}`)
}

export function testGitRepoConnection(id: number): Promise<{ success: boolean; message: string }> {
  return post(`/git-repos/${id}/test`)
}

export function syncGitRepo(id: number): Promise<{ message: string }> {
  return post(`/git-repos/${id}/sync`)
}
