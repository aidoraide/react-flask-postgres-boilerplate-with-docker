import React, { Component } from 'react';
import logo from './logo.svg';
import './App.css';
import { CONFIG } from './config.js';

class App extends Component {
  constructor() {
    super();
    this.state = {
        players: []
    };
  }

  async componentDidMount() {
    const res = await fetch(CONFIG.API_BASE_URL);
    const players = await res.json();
    console.log('players', players);
    this.setState({players: players});
  }

  render() {
    const players = this.state.players.map((player, index) => <li key={index}>{player.lastname} {player.firstname}</li>);

    return (
      <div>
          <h1>Players list</h1>
          <ul>
            {players}
          </ul>
      </div>
    );
  }
}

export default App;
