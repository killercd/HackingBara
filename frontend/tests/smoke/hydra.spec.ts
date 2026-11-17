import { test, expect } from '@playwright/test'

test('Hydra needs only user and password lists and retains encrypted saved passwords', async ({page}) => {
  let saved: Record<string, any> | undefined
  let updates = 0
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname
    const method = route.request().method()
    let json: unknown = {items: [], total: 0, total_pages: 0}
    if(path.endsWith('/auth/me')) json = {username: 'operator'}
    else if(path.endsWith('/capabilities')) json = {screenshots: true}
    else if((path.endsWith('/scans') && method==='POST') || (path.endsWith('/scans/hydra-scan') && method==='PATCH')) {
      const body = route.request().postDataJSON()
      expect(body).toMatchObject({password_spray: true, credential_auto_detect: true,
        hydra_usernames: ['operator', 'admin'], credential_services: [], credential_endpoints: [], credential_ids: []})
      if(method==='POST') expect(body.hydra_passwords).toEqual(['z-first-secret', 'a-second-secret'])
      else {expect(body.hydra_passwords).toBeNull(); updates++}
      const {hydra_passwords, ...config} = body
      saved = {...config, hydra_password_count: 2, credential_ids: ['pair-1', 'pair-2', 'pair-3', 'pair-4']}
      json = {id: 'hydra-scan'}
    } else if(path.endsWith('/scans/hydra-scan')) json = {id: 'hydra-scan', name: 'Hydra lists', config: {...saved, hostnames: []}, target_summary: '192.0.2.1'}
    await route.fulfill({json})
  })
  await page.goto('/scans/new')
  await page.getByLabel('Scan name').fill('Hydra lists')
  await page.getByLabel('Authorized IP addresses / CIDRs').fill('192.0.2.1')
  await page.getByLabel('TCP ports').fill('22,2222,2121')
  await page.getByLabel('Validate credentials with Hydra').check()
  await expect(page.getByRole('combobox', {name: 'Hydra module', exact: true})).toHaveCount(0)
  await expect(page.getByRole('button', {name: 'Add Hydra service', exact: true})).toHaveCount(0)
  await expect(page.getByLabel('Automatically validate discovered services')).toHaveCount(0)
  await page.getByLabel('Hydra usernames').fill('operator\nadmin')
  await page.getByLabel('Hydra passwords').fill('z-first-secret\na-second-secret')
  await page.getByRole('button', {name: 'Save scan', exact: true}).click()
  await expect(page.getByRole('heading', {name: 'Hydra lists', exact: true})).toBeVisible()
  await page.goto('/scans/hydra-scan/edit')
  await expect(page.getByLabel('Hydra usernames')).toHaveValue('operator\nadmin')
  await expect(page.getByLabel('Hydra passwords')).toHaveValue('')
  await expect(page.getByText('2 passwords saved securely.', {exact: false})).toBeVisible()
  await page.getByRole('button', {name: 'Save scan', exact: true}).click()
  await expect(page.getByRole('heading', {name: 'Hydra lists', exact: true})).toBeVisible()
  expect(updates).toBe(1)
})
