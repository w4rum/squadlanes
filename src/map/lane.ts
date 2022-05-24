export class Lane {
  public readonly name: string;
  public length: number = -1;
  public probability: number;

  constructor(name: string) {
    this.name = name;
    this.probability = 0.0;
  }
}
