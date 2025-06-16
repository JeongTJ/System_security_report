import logo from './logo.svg';
import './App.css';
import { useState } from 'react';
// URL 파라미터를 수집
const searchParams = new URLSearchParams(window.location.search);
const paramEntries = Array.from(searchParams.entries());

function App() {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');

  const handleInputChange = (e) => setInput(e.target.value);
  const handleButtonClick = () => setOutput(input);

  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo" />
        <p>
          Edit <code>src/App.js</code> and save to reload.
        </p>
        <input
          type="text"
          value={input}
          onChange={handleInputChange}
          placeholder="내용을 입력하세요"
          style={{ padding: '8px', width: '70%' }}
        />
        <button
          onClick={handleButtonClick}
          style={{ padding: '8px 16px', marginLeft: '8px' }}
        >
          입력
        </button>
        {output && (
          <div
            style={{ marginTop: '20px', fontSize: '1.2em', color: '#61dafb' }}
            dangerouslySetInnerHTML={{ __html: `입력한 내용: ${output}` }}
          />
        )}
        {/* URL 파라미터 표시 영역 */}
        {paramEntries.length > 0 && (
          <div style={{ marginTop: '20px', color: '#ffa500' }}>
            <h3>URL 파라미터</h3>
            {paramEntries.map(([key, value]) => (
              <div key={key}
                   dangerouslySetInnerHTML={{ __html: `${key}: ${value}` }} />
            ))}
          </div>
        )}
        <a
          className="App-link"
          href="https://reactjs.org"
          target="_blank"
          rel="noopener noreferrer"
        >
          Learn React
        </a>
      </header>
    </div>
  );
}

export default App;
