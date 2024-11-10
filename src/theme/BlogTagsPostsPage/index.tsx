import React from "react";
import clsx from "clsx";
import {
  PageMetadata,
  HtmlClassNameProvider,
  ThemeClassNames,
} from "@docusaurus/theme-common";
import BlogLayout from "@theme/BlogLayout";
import BlogListPaginator from "@theme/BlogListPaginator";
import SearchMetadata from "@theme/SearchMetadata";
import type { Props } from "@theme/BlogTagsPostsPage";
import BlogPostItems from "@theme/BlogPostItems";
import Unlisted from "@theme/ContentVisibility/Unlisted";

function BlogTagsPostsPageMetadata({ tag }: Props): JSX.Element {
  const title = tag.label;
  return (
    <>
      <PageMetadata title={title} description={tag.description} />
      <SearchMetadata tag="blog_tags_posts" />
    </>
  );
}

function BlogTagsPostsPageContent({
  tag,
  items,
  sidebar,
  listMetadata,
}: Props): JSX.Element {
  // 筛选包含该 tags 的 sidebar items
  const filteredSidebar = sidebar.items.filter((item) =>
    items.some((post) => post.content.metadata.permalink === item.permalink)
  );
  return (
    <BlogLayout sidebar={{ title: tag.label, items: filteredSidebar }}>
      {tag.unlisted && <Unlisted />}
      <BlogPostItems items={items} />
      <BlogListPaginator metadata={listMetadata} />
    </BlogLayout>
  );
}
export default function BlogTagsPostsPage(props: Props): JSX.Element {
  return (
    <HtmlClassNameProvider
      className={clsx(
        ThemeClassNames.wrapper.blogPages,
        ThemeClassNames.page.blogTagPostListPage
      )}
    >
      <BlogTagsPostsPageMetadata {...props} />
      <BlogTagsPostsPageContent {...props} />
    </HtmlClassNameProvider>
  );
}
