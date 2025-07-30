const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

async function testFastMode() {
    console.log('Testing fast mode...');

    const startTime = Date.now();

    try {
        const response = await fetch('http://localhost:3000/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                url: 'https://example.com',
                fast: true
            })
        });

        const endTime = Date.now();
        const duration = endTime - startTime;

        console.log(`Request completed in ${duration}ms`);

        if (response.ok) {
            const result = await response.json();
            console.log('Success!');
            console.log(`SSL Score: ${result.ssl.score}/${result.ssl.maxScore} (${result.ssl.grade})`);
        } else {
            const error = await response.text();
            console.log('Error:', response.status, error);
        }
    } catch (error) {
        console.error('Request failed:', error.message);
    }
}

testFastMode();
