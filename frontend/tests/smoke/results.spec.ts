import { test, expect } from '@playwright/test'

test('result headers sort, render response headers and export active filters', async ({page}) => {
  await page.route('**/api/v1/**', async route => {
    const url = new URL(route.request().url())
    let json: unknown = {items: [], total: 0, total_pages: 0}
    if(url.pathname.endsWith('/auth/me')) json = {username: 'operator'}
    else if(url.pathname.endsWith('/runs/result-run')) json = {
      id: 'result-run', config_snapshot: {mode: 'network', hostnames: ['web.example']},
      status: 'completed', counts: {}, processed: 1, total: 1,
    }
    else if(url.pathname.endsWith('/services')) json = {items: [{id: 'service', hostname: 'web.example',
      ip: '192.0.2.1', port: 443, details: {response_headers: [['Server', 'nginx'], ['X-Test', 'first'], ['X-Test', 'second']]}}], total: 1, total_pages: 1}
    await route.fulfill({json})
  })
  await page.goto('/scans/result-scan/runs/result-run?tab=services')
  await expect(page.getByRole('cell', {name: 'web.example', exact: true})).toBeVisible()
  await expect(page.locator('.response-headers')).toHaveText('Server: nginx\nX-Test: first\nX-Test: second')
  await page.getByRole('columnheader', {name: 'Port', exact: true}).getByRole('button').click()
  await expect(page.getByRole('columnheader', {name: 'Port', exact: true})).toHaveAttribute('aria-sort', 'ascending')
  await page.getByRole('columnheader', {name: 'Port', exact: true}).getByRole('button').click()
  await expect(page.getByRole('columnheader', {name: 'Port', exact: true})).toHaveAttribute('aria-sort', 'descending')
  await page.getByRole('searchbox').fill('web.example')
  await page.getByRole('button', {name: 'Search', exact: true}).click()
  await expect(page.getByRole('link', {name: 'Export CSV'})).toHaveAttribute('href', /services\/export\.csv\?search=web.example&status=&sort_by=port&sort_order=desc/)
  await expect(page.getByRole('button', {name: 'Findings', exact: true})).toHaveCount(0)
  await page.getByRole('button', {name: 'CVE', exact: true}).click()
  await expect(page.getByText('SearchSploit banner matches', {exact: false})).toBeVisible()
})
