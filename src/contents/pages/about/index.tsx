import React from 'react';
import Layout from '@theme/Layout';
import styles from './index.module.scss';

export default function Hello() {
  return (
    <Layout title="Hello" description="Hello React Page">
      <div
        style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          fontSize: '20px',
        }}>
        <div className={styles['board']}>
            
        </div>
      </div>
    </Layout>
  );
}