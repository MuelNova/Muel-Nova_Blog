import React from 'react';
import BlogPostPaginator from '@theme-original/BlogPostPaginator';
import GiscusComment from '@site/src/theme/components/GiscusComment/GiscusComment';
// import DownloadImageButton from '@site/src/theme/components/BlogDownloader/BlogDownloader';


export default function BlogPostPaginatorWrapper(props) {
  return (
    <>
      <BlogPostPaginator {...props} />
      <GiscusComment />
    </>
  );
}
