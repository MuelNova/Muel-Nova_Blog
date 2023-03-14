import React from 'react';
import BlogPostPaginator from '@theme-original/BlogPostPaginator';
import GitalkComment from '@site/src/theme/GitalkComment';

export default function BlogPostPaginatorWrapper(props) {
  return (
    <>
      <BlogPostPaginator {...props} />
      <GitalkComment />
    </>
  );
}
