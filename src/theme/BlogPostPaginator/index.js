import React from 'react';
import BlogPostPaginator from '@theme-original/BlogPostPaginator';
import GiscusComment from '@site/src/theme/components/GiscusComment/GiscusComment';

export default function BlogPostPaginatorWrapper(props) {
  return (
    <>
      <BlogPostPaginator {...props} />
      <GiscusComment />
    </>
  );
}
