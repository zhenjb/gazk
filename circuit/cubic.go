package circuit

import "github.com/consensys/gnark/frontend"

// CubicCircuit define a circuit that checks that y = x^3 + x + 5
type CubicCircuit struct {
	X frontend.Variable `gnark:",secret"`
	Y frontend.Variable `gnark:",public"`
}

//Define defines the circuit constraints
func (circuit *CubicCircuit) Define(api frontend.API) error {
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	r := api.Add(x3, circuit.X, 5)
	api.AssertIsEqual(circuit.Y, r)
	return nil
}
