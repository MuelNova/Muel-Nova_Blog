import React, { useEffect } from 'react'
import { useThemeConfig, useColorMode } from '@docusaurus/theme-common'
import useDocusaurusContext from '@docusaurus/useDocusaurusContext'
import { ThemeConfig } from '@docusaurus/preset-classic'
import BrowserOnly from '@docusaurus/BrowserOnly'
import Giscus, { GiscusProps } from '@giscus/react'

interface CustomThemeConfig extends ThemeConfig {
  giscus: GiscusProps & { lightCss: string; darkCss: string }
}

const defaultConfig: Partial<GiscusProps> = {
  id: 'comments',
  mapping: 'title',
  reactionsEnabled: '1',
  emitMetadata: '0',
  inputPosition: 'top',
  lang: 'zh-CN'
}

export default (): JSX.Element => {
  const themeConfig = useThemeConfig() as CustomThemeConfig
  const { i18n } = useDocusaurusContext()

  // merge default config
  const giscus = { ...defaultConfig, ...themeConfig.giscus }

  if (!giscus.repo || !giscus.repoId || !giscus.categoryId) {
    throw new Error(
      'You must provide `repo`, `repoId`, and `categoryId` to `themeConfig.giscus`.',
    )
  }

  giscus.lang = i18n.currentLocale
  giscus.theme = useColorMode().colorMode === 'dark' ? giscus.darkCss || 'transparent_dark' : giscus.lightCss || 'light'
  

  return (
    <BrowserOnly fallback={<div>Loading Comments...</div>}>
      {() => <Giscus {...giscus} />}
    </BrowserOnly>
  )
}