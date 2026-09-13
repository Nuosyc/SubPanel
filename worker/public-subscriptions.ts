import { Hono } from 'hono'
import type { Context } from 'hono'
import type { AppEnv } from './app-env.js'
import { readCatalog } from './catalog/repository.js'
import { apiError } from './platform/api-error.js'
import { hashToken } from './platform/crypto.js'
import { compiledArtifactSchema } from './delivery/schema.js'
import { compileSubscription } from './delivery/compiler.js'
import { compiledKey, readDelivery } from './delivery/repository.js'

const tokenPattern = /^[A-Za-z0-9_-]{43}$/u
const clients = new Set(['mihomo', 'singbox', 'quantumultx', 'v2rayn', 'nekobox', 'shadowrocket', 'generic'])
const clientAliases: Record<string, string> = {
  clash: 'mihomo',
  'clash-meta': 'mihomo',
  stash: 'mihomo',
  karing: 'singbox',
  'sing-box': 'singbox',
  'quantumult-x': 'quantumultx',
  v2rayng: 'v2rayn',
  'neko-box': 'nekobox',
}

function clientFromUserAgent(userAgent: string): string {
  const value = userAgent.toLowerCase()
  if (value.includes('mihomo') || value.includes('clash') || value.includes('stash')) return 'mihomo'
  if (value.includes('sing-box') || value.includes('singbox') || value.includes('karing')) return 'singbox'
  if (value.includes('quantumult')) return 'quantumultx'
  if (value.includes('v2rayn') || value.includes('v2rayng')) return 'v2rayn'
  if (value.includes('nekobox')) return 'nekobox'
  if (value.includes('shadowrocket')) return 'shadowrocket'
  return 'generic'
}

async function serve(c: Context<AppEnv>, clientParam?: string) {
  const token = c.req.param('token') ?? ''
  if (!tokenPattern.test(token)) throw apiError(404, 'SUBSCRIPTION_NOT_FOUND', '订阅不存在')
  const requestedClient = clientParam ?? clientFromUserAgent(c.req.header('User-Agent') ?? '')
  const client = clientAliases[requestedClient.toLowerCase()] ?? requestedClient.toLowerCase()
  if (!clients.has(client)) throw apiError(404, 'SUBSCRIPTION_CLIENT_NOT_FOUND', '订阅格式不存在')
  const tokenHash = await hashToken(token)

  // 每次都读取权威状态（delivery）以校验 enabled/revision，保证停用、删除、重置 token 即时生效
  let subscription
  try {
    const delivery = await readDelivery(c.env.DATA)
    subscription = delivery.subscriptions.find((candidate) => candidate.tokenHash === tokenHash)
  } catch {
    throw apiError(404, 'SUBSCRIPTION_NOT_FOUND', '订阅不存在')
  }
  if (!subscription?.enabled) throw apiError(404, 'SUBSCRIPTION_NOT_FOUND', '订阅不存在')

  // 缓存键包含所属客户端与订阅版本，内容（版本）变化即换新键
  const cacheUrl = new URL(c.req.url)
  cacheUrl.search = `__s=${subscription.revision}&__c=${client}`
  const cacheKey = new Request(cacheUrl)
  const cached = await caches.default.match(cacheKey)
  if (cached) {
    const cachedEtag = cached.headers.get('etag')
    const ifNoneMatch = c.req.header('If-None-Match')
    if (cachedEtag && ifNoneMatch?.split(',').map((value: string) => value.trim()).includes(cachedEtag)) {
      return new Response(null, { status: 304, headers: { ETag: cachedEtag } })
    }
    return cached
  }

  let raw: string | null
  let catalog: Awaited<ReturnType<typeof readCatalog>>
  try {
    [raw, catalog] = await Promise.all([
      c.env.DATA.get(compiledKey(tokenHash, client)),
      readCatalog(c.env.DATA),
    ])
  } catch {
    throw apiError(404, 'SUBSCRIPTION_NOT_FOUND', '订阅不存在')
  }
  if (!raw) throw apiError(404, 'SUBSCRIPTION_NOT_FOUND', '订阅不存在')
  let value: unknown
  try {
    value = JSON.parse(raw)
  } catch {
    throw apiError(404, 'SUBSCRIPTION_NOT_FOUND', '订阅不存在')
  }
  const parsed = compiledArtifactSchema.safeParse(value)
  let artifact
  if (parsed.success) artifact = parsed.data
  else if (value !== null && typeof value === 'object' && !Array.isArray(value) && 'schemaVersion' in value && value.schemaVersion === 1) {
    try {
      artifact = (await compileSubscription(c.env.DATA, subscription)).find((candidate) => candidate.client === client)
    } catch {
      throw apiError(404, 'SUBSCRIPTION_NOT_FOUND', '订阅不存在')
    }
    if (!artifact) throw apiError(404, 'SUBSCRIPTION_NOT_FOUND', '订阅不存在')
  } else throw apiError(404, 'SUBSCRIPTION_NOT_FOUND', '订阅不存在')
  if (artifact.subscriptionRevision !== subscription.revision || artifact.catalogRevision !== catalog.revision) {
    throw apiError(404, 'SUBSCRIPTION_NOT_FOUND', '订阅不存在')
  }
  if (!artifact.available) throw apiError(422, 'SUBSCRIPTION_NO_NODES', '该订阅没有可用节点')
  c.header('ETag', artifact.etag)
  c.header('Last-Modified', new Date(artifact.lastModified).toUTCString())
  c.header('Content-Type', artifact.contentType)
  const extension = artifact.fileName.includes('.') ? artifact.fileName.slice(artifact.fileName.lastIndexOf('.')) : ''
  c.header('Content-Disposition', `attachment; filename="${artifact.fileName.replaceAll('"', '')}"; filename*=UTF-8''${encodeURIComponent(`${subscription.name}${extension}`)}`)
  c.header('profile-title', encodeURIComponent(subscription.name))
  const ifNoneMatch = c.req.header('If-None-Match')
  if (ifNoneMatch?.split(',').map((value: string) => value.trim()).includes(artifact.etag)) return c.body(null, 304)
  const response = c.body(artifact.body)
  response.headers.set('Cache-Control', 'public, max-age=1800')
  await caches.default.put(cacheKey, response.clone())
  return response
}

export const publicSubscriptionRoutes = new Hono<AppEnv>()
publicSubscriptionRoutes.get('/sub/:token', (c) => serve(c))
publicSubscriptionRoutes.get('/sub/:token/:client', (c) => serve(c, c.req.param('client')))
