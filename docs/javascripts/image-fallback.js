/* 图床三级兜底
 *
 * 2026-10 实测（国内出口）：cdn.jsdelivr.net 被重置、raw.gitmirror.com 域名已停、
 * fastly.jsdelivr.net 与 jsd.onmicrosoft.cn 会 301 回源到国内不通的 raw.githubusercontent.com。
 * 因此正文图片统一走 gcore.jsdelivr.net，本脚本负责它在个别时段失效时的降级：
 *   主   gcore.jsdelivr.net
 *   备   testingcf.jsdelivr.net          同属 Cloudflare 节点
 *   兜底 gh-proxy.com + raw.githubusercontent.com
 */
document.addEventListener(
  'error',
  function (e) {
    var img = e.target;
    if (!img || img.tagName !== 'IMG') return;

    var n = parseInt(img.dataset.retried || '0', 10) + 1;
    img.dataset.retried = String(n);

    if (n === 1) {
      img.src = img.src.replace('gcore.jsdelivr.net', 'testingcf.jsdelivr.net');
    } else if (n === 2) {
      img.src = img.src
        .replace('testingcf.jsdelivr.net/gh/', 'gh-proxy.com/https://raw.githubusercontent.com/')
        .replace('@main/', 'main/');
    } else {
      img.alt = (img.alt || '') + '（图片加载失败）';
    }
  },
  true
);
