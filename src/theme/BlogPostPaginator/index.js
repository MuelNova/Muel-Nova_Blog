import React from 'react';
import BlogPostPaginator from '@theme-original/BlogPostPaginator';
import GitalkComment from '@site/src/theme/components/GitalkComment/GitalkComment';

export default function BlogPostPaginatorWrapper(props) {
  return (
    <>
      <BlogPostPaginator {...props} />
      <GitalkComment />
    </>
  );
}
