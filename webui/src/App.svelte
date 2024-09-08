<script>
	let messages = [];
	let newMessage = '';

	function sendMessage() {
		if (newMessage.trim()) {
			messages = [
				...messages, 
				{ text: newMessage, sender: 'user' },
				{ text: 'lol', sender: 'bot' }
			];
			newMessage = '';
		}
	}
</script>

<svelte:head>
	<style>
		@font-face {
			font-family: 'Early GameBoy';
			src: url('/EarlyGameBoy.ttf') format('truetype');
			font-weight: normal;
			font-style: normal;
		}
	</style>
</svelte:head>

<main>
	<div class="nintendo-console">
		<div class="screen">
			<div class="message-list">
				{#each messages as message}
					<div class="message {message.sender}">
						{message.text}
					</div>
				{/each}
			</div>
		</div>
		<div class="controls">
			<input
				type="text"
				bind:value={newMessage}
				on:keypress={(e) => e.key === 'Enter' && sendMessage()}
				placeholder="Type a message..."
			/>
			<button on:click={sendMessage}>SEND</button>
		</div>
	</div>
</main>

<style>
	:global(body) {
		font-family: 'Early GameBoy', cursive;
		background-color: #8b8b8b;
		margin: 0;
		padding: 20px;
		display: flex;
		justify-content: center;
		align-items: center;
		height: 100vh;
	}

	.nintendo-console {
		background-color: #c4c4c4;
		border: 20px solid #747474;
		border-radius: 20px;
		padding: 20px;
		max-width: 500px;
		width: 100%;
	}

	.screen {
		background-color: #9bbc0f;
		border: 10px solid #8bac0f;
		border-radius: 10px;
		padding: 20px;
		height: 300px;
		overflow-y: auto;
	}

	.message-list {
		display: flex;
		flex-direction: column;
	}

	.message {
		margin-bottom: 10px;
		padding: 5px;
		border-radius: 5px;
		font-size: 12px;
		line-height: 1.4;
		word-wrap: break-word;
	}

	.user {
		align-self: flex-end;
		background-color: #306230;
		color: #9bbc0f;
	}

	.bot {
		align-self: flex-start;
		background-color: #0f380f;
		color: #9bbc0f;
	}

	.controls {
		margin-top: 20px;
		display: flex;
		gap: 10px;
	}

	input {
		flex-grow: 1;
		font-family: 'Early GameBoy', cursive;
		font-size: 12px;
		padding: 10px;
		background-color: #9bbc0f;
		border: 5px solid #306230;
		color: #0f380f;
	}

	button {
		font-family: 'Early GameBoy', cursive;
		font-size: 12px;
		padding: 10px 20px;
		background-color: #ff0000;
		border: 5px solid #8b1a1a;
		color: #ffffff;
		cursor: pointer;
	}

	button:active {
		background-color: #8b1a1a;
	}
</style>