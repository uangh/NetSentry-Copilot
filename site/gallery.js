// Only switches local, real screenshots. No API calls or generated demo state.
document.querySelectorAll('[data-shot]').forEach(button=>{
  button.setAttribute('aria-pressed',button.classList.contains('active')?'true':'false');
  button.addEventListener('click',()=>{
    document.querySelectorAll('[data-shot]').forEach(other=>{other.classList.remove('active');other.setAttribute('aria-pressed','false');});
    button.classList.add('active');button.setAttribute('aria-pressed','true');
    const image=document.getElementById('gallery-image');
    image.src='assets/'+button.dataset.shot;image.alt=button.dataset.caption;
    document.getElementById('gallery-open').href=image.getAttribute('src');
    document.getElementById('gallery-caption').textContent=button.dataset.caption+'。点击图片查看原尺寸。';
  });
});
