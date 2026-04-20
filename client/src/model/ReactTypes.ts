export interface State<T> {
    value: T;
    setValue: (value: T) => void;
}