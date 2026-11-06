import {describe,it,expect,vi,afterEach} from 'vitest';
import {request,setToken,api} from '../api';
afterEach(()=>{setToken('');vi.unstubAllGlobals()});
describe('typed local API boundary',()=>{
 it('blocks external URLs',async()=>{await expect(request('https://example.org/api')).rejects.toThrow('本地')});
 it('requires a token before write',async()=>{await expect(api.start('a'.repeat(32))).rejects.toThrow('令牌')});
 it('rejects invalid record id',()=>{expect(()=>api.flow('fake')).toThrow('ID')});
 it('sends token only as write header, not URL or storage',async()=>{setToken('synthetic-memory-secret');const fn=vi.fn().mockResolvedValue(new Response('{}'));vi.stubGlobal('fetch',fn);await api.start('a'.repeat(32));const [url,options]=fn.mock.calls[0];expect(url).not.toContain('secret');expect(options.headers['X-API-Token']).toBe('synthetic-memory-secret');expect(localStorage.length).toBe(0);expect(sessionStorage.length).toBe(0)});
 it('does not include token in read requests',async()=>{setToken('synthetic');const fn=vi.fn().mockResolvedValue(new Response('{}'));vi.stubGlobal('fetch',fn);await api.health();expect(fn.mock.calls[0][1].headers).not.toHaveProperty('X-API-Token')});
 it.each([401,404,409,413,422,500,503])('handles HTTP %i without mock fallback',async status=>{vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response('{"error":{"trace_id":"trace"}}',{status})));await expect(api.health()).rejects.toHaveProperty('status',status)});
 it('reports disconnected backend',async()=>{vi.stubGlobal('fetch',vi.fn().mockRejectedValue(new TypeError('offline')));await expect(api.health()).rejects.toThrow('无法连接')});
 it('rejects leaked ground truth',async()=>{vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response('{"nested":{"attackID":"secret"}}')));await expect(api.health()).rejects.toThrow('离线标签')});
 it('refuses invalid JSON',async()=>{vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response('<html>error</html>')));await expect(api.health()).rejects.toThrow('JSON')});
 it('times out rather than silently retrying',async()=>{vi.useFakeTimers();vi.stubGlobal('fetch',vi.fn((_u,o)=>new Promise((_resolve,reject)=>o.signal.addEventListener('abort',()=>reject(new DOMException('abort','AbortError'))))));const promise=expect(api.health()).rejects.toThrow('超时');await vi.advanceTimersByTimeAsync(15001);await promise;vi.useRealTimers()});
});
