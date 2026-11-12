export function csrfToken(cookie = document.cookie): string {
  return decodeURIComponent(cookie.split('; ').find(x => x.startsWith('hb_csrf='))?.split('=').slice(1).join('=') || '')
}
export async function api(path: string, method = 'GET', body?: unknown) {
  const response = await fetch('/api/v1' + path, {method, credentials:'same-origin',
    headers:{'Content-Type':'application/json', 'X-CSRF-Token':csrfToken()},
    body:body === undefined ? undefined : JSON.stringify(body)})
  if (response.status === 401 && !path.startsWith('/auth/')) window.location.assign('/login')
  if (!response.ok) {
    const data = await response.json().catch(() => null)
    const details = data?.error?.details?.map((x: {field:string,message:string}) => `${x.field}: ${x.message}`).join('\n')
    const message = data?.error?.message || `Request failed (${response.status})`
    throw new Error(details ? `${message}\n${details}` : message)
  }
  return response.status === 204 ? null : response.json()
}
export function lines(value: string) {return value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean)}
