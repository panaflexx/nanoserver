// script.js

const feedContainer = document.getElementById('feed-container');
let page = 1;
let loading = false;

async function fetchPosts(pageNum, count = 10) {
  await new Promise(resolve => setTimeout(resolve, 300 + Math.random() * 400));

  const types = ['text', 'single-media', 'multi-media', 'big-text'];
  const sampleImages = [
    'https://picsum.photos/600/400?random=',
    'https://picsum.photos/500/700?random=',
    'https://picsum.photos/800/600?random=',
    'https://picsum.photos/400/600?random='
  ];
  const sampleVideos = [
    'clip1.mp4',
    'clip2.mp4',
    'clip3.mp4'
  ];

  const longText = `This is a very long text post to demonstrate the expand/shrink feature. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.`;

  const posts = [];

  for (let i = 0; i < count; i++) {
    const type = types[Math.floor(Math.random() * types.length)];
    const id = (pageNum - 1) * count + i + 1;
    const commentsCount = Math.floor(Math.random() * 10);

    const comments = [];
    for (let j = 0; j < Math.min(commentsCount, 5); j++) {
      comments.push({
        author: `User${Math.floor(Math.random() * 100)}`,
        text: `Comment ${j + 1} on post ${id}`
      });
    }

    const post = {
      id,
      user: `User${id}`,
      timestamp: 'Just now',
      type,
      text: type === 'text' 
        ? (Math.random() > 0.4 ? longText.repeat(Math.floor(Math.random() * 4) + 2) : 'Short text post.')
        : '',
      quote: type === 'big-text' ? `Inspiring quote or big text post #${id}` : '',
      media: [],
      comments: comments.slice(0, 3)
    };

    if (type === 'single-media') {
      const isVideo = Math.random() > 0.5;
      post.media = [{
        type: isVideo ? 'video' : 'image',
        url: isVideo ? `${sampleVideos[Math.floor(Math.random() * sampleVideos.length)]}` : `${sampleImages[0]}${id}`
      }];
    } else if (type === 'multi-media') {
      const mediaCount = Math.floor(Math.random() * 3) + 2;
      post.media = [];
      for (let j = 0; j < mediaCount; j++) {
        const isVideo = Math.random() > 0.5;
        post.media.push({
          type: isVideo ? 'video' : 'image',
          url: isVideo ? `${sampleVideos[Math.floor(Math.random() * sampleVideos.length)]}` : `${sampleImages[j % sampleImages.length]}${id + j}`
        });
      }
    }

    posts.push(post);
  }

  return posts;
}

function renderPostContent(post) {
  if (post.type === 'text' && post.text) {
    return `
      <div class="text-container">
        <div class="post-text ${post.text.length > 400 ? 'truncated' : ''}">${post.text}</div>
        ${post.text.length > 400 ? '<button class="show-more">Show more</button>' : ''}
      </div>
    `;
  } else if (post.type === 'single-media' && post.media.length) {
    const item = post.media[0];
    if (item.type === 'image') {
      return `<img class="post-media-single" src="${item.url}" alt="Post media">`;
    } else {
      // Added poster attribute using a placeholder image (picsum for demo)
      // Replace with actual thumbnails if available, or generate client-side
      return `<video class="post-media-single" controls poster="https://picsum.photos/600/600?random=${item.url}" src="${item.url}"></video>`;
    }
  } else if (post.type === 'multi-media' && post.media.length) {
    const count = post.media.length;
    let html = `<div class="post-media" data-count="${count}">`;
    post.media.forEach(item => {
      if (item.type === 'image') {
        html += `<img src="${item.url}" alt="Post media">`;
      } else {
        // Added poster attribute for multi-media videos too
        html += `<video controls poster="https://picsum.photos/300/300?random=${item.url}" src="${item.url}"></video>`;
      }
    });
    html += `</div>`;
    return html;
  } else if (post.type === 'big-text') {
    return `<div class="big-text">${post.quote}</div>`;
  }
  return '';
}

function createPost(postData) {
  const postEl = document.createElement('div');
  postEl.className = 'post';
  postEl.dataset.postId = postData.id;

  const commentsHtml = postData.comments.length > 0
    ? `<div class="comments">
        ${postData.comments.map(c => 
          `<div class="comment">
            <span class="comment-author">${c.author}</span>
            <span>${c.text}</span>
          </div>`
        ).join('')}
      </div>`
    : '';

  postEl.innerHTML = `
    <div class="post-main">
      <div class="post-header">
        <div class="avatar"></div>
        <div>
          <div class="username">${postData.user}</div>
          <div class="timestamp">${postData.timestamp}</div>
        </div>
      </div>
      <div class="post-content">
        ${renderPostContent(postData)}
      </div>
      <div class="actions">
        <button class="action-btn like-btn" data-liked="false">♡ Like</button>
        <button class="action-btn">💬 Comment</button>
        <button class="action-btn">↗️ Share</button>
      </div>
    </div>
    ${commentsHtml}
  `;

  // Attach event listener after setting innerHTML
  const textEl = postEl.querySelector('.post-text');
  const toggleBtn = postEl.querySelector('.show-more');
  if (toggleBtn && textEl) {
    toggleBtn.onclick = () => {
      if (textEl.classList.contains('truncated')) {
        textEl.classList.remove('truncated');
        textEl.classList.add('expanded');
        toggleBtn.textContent = 'Show less';
        toggleBtn.className = 'show-less';
      } else {
        textEl.classList.remove('expanded');
        textEl.classList.add('truncated');
        toggleBtn.textContent = 'Show more';
        toggleBtn.className = 'show-more';
      }
    };
  }
  // Like button interaction
  const likeBtn = postEl.querySelector('.like-btn');
  if (likeBtn) {
	 likeBtn.onclick = () => {
	   const isLiked = likeBtn.dataset.liked === 'true';
	   const postId = postData.id;

	   // Fake backend call
	   console.log(`User ${isLiked ? 'unliked' : 'liked'} post ${postId}`);
	   // In a real app: await fetch(`/api/posts/${postId}/like`, { method: isLiked ? 'DELETE' : 'POST' });

	   if (isLiked) {
		 likeBtn.dataset.liked = 'false';
		 likeBtn.innerHTML = '♡ Like';
	   } else {
		 likeBtn.dataset.liked = 'true';
		 likeBtn.innerHTML = '❤️ Liked';
	   }
     };
  }

  return postEl;
}

async function loadPosts() {
  if (loading) return;
  loading = true;

  const loadingEl = document.querySelector('.loading') || document.createElement('div');
  loadingEl.className = 'loading';
  loadingEl.textContent = 'Loading...';
  feedContainer.appendChild(loadingEl);

  try {
    const posts = await fetchPosts(page);
    loadingEl.remove();

    posts.forEach(postData => {
      feedContainer.appendChild(createPost(postData));
    });

    page++;
  } catch (err) {
    loadingEl.textContent = 'Error loading posts';
    console.error(err);
  } finally {
    loading = false;
  }
}

loadPosts();

feedContainer.addEventListener('scroll', () => {
  if (feedContainer.scrollTop + feedContainer.clientHeight >= feedContainer.scrollHeight - 100) {
    loadPosts();
  }
});
