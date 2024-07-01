import React, {type ReactNode} from 'react';
import clsx from 'clsx';
import {HtmlClassNameProvider, ThemeClassNames} from '@docusaurus/theme-common';
import {BlogPostProvider, useBlogPost} from '@docusaurus/theme-common/internal';
import BlogLayout from '@theme/BlogLayout';
import BlogPostItem from '@theme/BlogPostItem';
import BlogPostPaginator from '@theme/BlogPostPaginator';
import BlogPostPageMetadata from '@theme/BlogPostPage/Metadata';
import BlogPostPageStructuredData from '@theme/BlogPostPage/StructuredData';
import TOC from '@theme/TOC';
import type {Props} from '@theme/BlogPostPage';
import Unlisted from '@theme/Unlisted';
import type {BlogSidebar} from '@docusaurus/plugin-content-blog';
import Markdown from 'react-markdown';
import Admonition from '@theme/Admonition';
import TypeIt from "typeit-react";



function BlogPostPageContent({
  sidebar,
  children,
}: {
  sidebar: BlogSidebar;
  children: ReactNode;
}): JSX.Element {
  const {metadata, toc} = useBlogPost();
  const {nextItem, prevItem, frontMatter, unlisted} = metadata;
  const {
    hide_table_of_contents: hideTableOfContents,
    toc_min_heading_level: tocMinHeadingLevel,
    toc_max_heading_level: tocMaxHeadingLevel,
  } = frontMatter;
  return (
    <BlogLayout
      sidebar={sidebar}
      toc={
        !hideTableOfContents && toc.length > 0 ? (
          <TOC
            toc={toc}
            minHeadingLevel={tocMinHeadingLevel}
            maxHeadingLevel={tocMaxHeadingLevel}
          />
        ) : undefined
      }>
      {unlisted && <Unlisted />}

      <BlogPostItem>{children}</BlogPostItem>

      {(nextItem || prevItem) && (
        <BlogPostPaginator nextItem={nextItem} prevItem={prevItem} />
      )}
    </BlogLayout>
  );
}

function BlogSummary(props: Props): JSX.Element {
  try {
    const Data = require('@site/.docusaurus/ai-summary/default/aisummary.json');
    const link = props.content.metadata.editUrl.split('/');
    const blog = link[link.length-2], post = link[link.length-1].replace(/\.(md|mdx)$/, '');
    if (!Data[blog] || !Data[blog][post]) {
      console.warn('No ai-summary content found, skipping AI summary generation');
      return <></>
    }
    const summary = Data[blog][post];
    
    return (
      <Admonition type="danger" title="AI Summary" icon='🤖'>
        <TypeIt options={{speed: 7, cursor: false}}>
          <Markdown>
            {summary}
          </Markdown>
        </TypeIt>
      </Admonition>
    )
  }
  catch (e) {
    console.warn(e)
    console.warn('No ai-summary plugin found, skipping AI summary generation');
    return <></>
  }
}

export default function BlogPostPage(props: Props): JSX.Element {
  const BlogPostContent = props.content;
  return (
    <BlogPostProvider content={props.content} isBlogPostPage>
      <HtmlClassNameProvider
        className={clsx(
          ThemeClassNames.wrapper.blogPages,
          ThemeClassNames.page.blogPostPage,
        )}>
        <BlogPostPageMetadata />
        <BlogPostPageStructuredData />
        <BlogPostPageContent sidebar={props.sidebar}>
          <BlogSummary {...props}/>
          <BlogPostContent />
        </BlogPostPageContent>
      </HtmlClassNameProvider>
    </BlogPostProvider>
  );
}
