import React from 'react';
import styles from './about.module.scss';

const Svg = ({ Svg, link }) => {
  return (
    <a href={link} target='_blank'>
      <Svg className={styles['last-chapter__sns-nav']} />
    </a>
  )
}
const svgList = [
  {
    title: 'bilibili',
    Svg: require('@site/static/img/bilibili.svg').default,
    link: 'https://space.bilibili.com/11966801'
  },
  {
    title: 'github',
    Svg: require('@site/static/img/github.svg').default,
    link: 'https://github.com/Nova-Noir'
  }
]

function AboutComponent() {
  
    return (
        <article className={styles['last-chapter']}>
        <div className={styles['last-chapter__bg-help']} />
        <div className={styles['last-chapter__bg']} />
        <div className={styles['last-chapter__ball']} />
        <div className={styles['last-chapter__frame']}>
          <div />
          <div />
          <div />
          <div />
        </div>
        <div className={styles['last-chapter__decoration']}>
          <div className={styles['star']} />
          <div className={styles['star']} />
          <div className={styles['star']} />
          <div className={styles['star']} />
          <div className={styles['moon']} />
        </div>
        <div className={styles['last-chapter__logo']} />
        <nav className={styles['last-chapter__sns-nav']}>
          { svgList.map((item, _) => {
            return <Svg {...item} key={item.title}/>
          })}
        </nav>

        <button type="button" className={styles['last-chapter__menu-btn']}>
          <div />
          <div />
          <div />
        </button>
      </article>    
    );
}

export default function Home(): JSX.Element {
    return (
        <main>
          <AboutComponent />
        </main>
    );
  }
  