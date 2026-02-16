export class Vehicle {
    constructor(
        public id: string,
        public name: string,
        public lat: number,
        public lon: number,
        public connected: boolean,
    ) {}

    static fromJson(data: any) {
        return new Vehicle(
            data['Id'],
            data['Name'],
            data['Lat'],
            data['Lon'],
            data['Connected']
        )
    }
}
